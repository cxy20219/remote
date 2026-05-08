import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

class TunnelService {
  Process? _process;
  bool _running = false;
  String? _clientId;
  Timer? _heartbeatCheck;
  final _statusController = StreamController<TunnelState>.broadcast();

  static const agentAsset = 'assets/agent-android-arm64';
  static const agentName = 'go-remote-agent';

  Stream<TunnelState> get status => _statusController.stream;
  bool get isRunning => _running;
  String? get clientId => _clientId;

  /// Extract the agent binary from assets to app storage and make it executable.
  Future<String> _prepareBinary() async {
    final dir = await getApplicationDocumentsDirectory();
    final binary = File('${dir.path}/$agentName');

    if (!await binary.exists()) {
      final data = await rootBundle.load(agentAsset);
      await binary.writeAsBytes(data.buffer.asUint8List());
      // chmod +x equivalent on Android
      final result = await Process.run('chmod', ['+x', binary.path]);
      if (result.exitCode != 0) {
        throw Exception('Failed to make agent executable: ${result.stderr}');
      }
    }
    return binary.path;
  }

  /// Generate agent config YAML.
  String _buildConfig(String serverAddr, String authKey, int localPort) {
    return '''
server:
  address: "$serverAddr"
  tls:
    enabled: true
    insecure_skip_verify: true
auth:
  key: "$authKey"
agent:
  hostname: "android-adb"
  os: "android"
heartbeat:
  interval: 30
reconnect:
  interval: 5
  max_interval: 60
log:
  level: "info"
tunnel:
  enabled: true
''';
  }

  /// Start the Go agent tunnel.
  Future<void> start({
    required String serverAddr,
    required String authKey,
    required int localPort,
  }) async {
    if (_running) return;

    try {
      _statusController.add(TunnelState.connecting);

      final binary = await _prepareBinary();
      final dir = await getApplicationDocumentsDirectory();
      final configFile = File('${dir.path}/agent.yaml');
      await configFile.writeAsString(_buildConfig(serverAddr, authKey, localPort));

      _process = await Process.start(binary, ['--config', configFile.path]);
      _running = true;

      // Monitor stdout for registration confirmation
      _process!.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
        if (line.contains('client_id')) {
          try {
            final log = jsonDecode(line);
            _clientId = log['client_id'];
            _statusController.add(TunnelState.connected);
          } catch (_) {}
        }
        if (line.contains('registered successfully')) {
          _statusController.add(TunnelState.connected);
        }
      });

      _process!.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
        if (line.contains('failed') || line.contains('error')) {
          _statusController.add(TunnelState.error(line));
        }
      });

      // Monitor process exit
      _process!.exitCode.then((code) {
        _running = false;
        _clientId = null;
        if (code != 0) {
          _statusController.add(TunnelState.disconnected('Agent exited with code $code'));
        } else {
          _statusController.add(TunnelState.disconnected);
        }
      });

      // Heartbeat check — if no connected signal within 10s, assume failure
      _heartbeatCheck = Timer(const Duration(seconds: 10), () {
        if (_running && _clientId == null) {
          _statusController.add(TunnelState.error('Connection timeout'));
        }
      });
    } catch (e) {
      _running = false;
      _statusController.add(TunnelState.error(e.toString()));
      rethrow;
    }
  }

  /// Stop the agent process.
  Future<void> stop() async {
    _heartbeatCheck?.cancel();
    if (_process != null) {
      _process!.kill(ProcessSignal.sigterm);
      _process = null;
    }
    _running = false;
    _clientId = null;
    _statusController.add(TunnelState.stopped);
  }

  void dispose() {
    _statusController.close();
    _heartbeatCheck?.cancel();
    stop();
  }
}

enum TunnelStatus { connecting, connected, disconnected, error, stopped }

class TunnelState {
  final TunnelStatus status;
  final String? message;

  const TunnelState._(this.status, [this.message]);

  static const connecting = TunnelState._(TunnelStatus.connecting);
  static const connected = TunnelState._(TunnelStatus.connected);
  static const disconnected = TunnelState._(TunnelStatus.disconnected);
  static const stopped = TunnelState._(TunnelStatus.stopped);
  static TunnelState error(String msg) => TunnelState._(TunnelStatus.error, msg);
  static TunnelState disconnectedWithMsg(String msg) =>
      TunnelState._(TunnelStatus.disconnected, msg);
}
