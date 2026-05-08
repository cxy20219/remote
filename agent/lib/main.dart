import 'dart:async';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'tunnel_service.dart';

void main() => runApp(const ADBTunnelApp());

class ADBTunnelApp extends StatelessWidget {
  const ADBTunnelApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'GoRemote ADB',
      theme: ThemeData(
        colorSchemeSeed: const Color(0xFF3B82F6),
        useMaterial3: true,
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        colorSchemeSeed: const Color(0xFF3B82F6),
        useMaterial3: true,
        brightness: Brightness.dark,
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final _service = TunnelService();
  final _serverCtrl = TextEditingController(text: 'your-server:8080');
  final _keyCtrl = TextEditingController(text: 'test-secret-key');
  final _portCtrl = TextEditingController(text: '5555');

  TunnelStatus _status = TunnelStatus.stopped;
  String? _statusMsg;
  StreamSubscription? _sub;
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    _sub = _service.status.listen((s) {
      if (!mounted) return;
      setState(() {
        _status = s.status;
        _statusMsg = s.message;
      });
    });
    _loadPrefs();
  }

  Future<void> _loadPrefs() async {
    final p = await SharedPreferences.getInstance();
    _serverCtrl.text = p.getString('server') ?? 'your-server:8080';
    _keyCtrl.text = p.getString('key') ?? 'test-secret-key';
    _portCtrl.text = p.getString('port') ?? '5555';
  }

  Future<void> _savePrefs() async {
    final p = await SharedPreferences.getInstance();
    await p.setString('server', _serverCtrl.text);
    await p.setString('key', _keyCtrl.text);
    await p.setString('port', _portCtrl.text);
  }

  Future<void> _toggle() async {
    if (_loading) return;
    if (_service.isRunning) {
      await _service.stop();
    } else {
      setState(() => _loading = true);
      await _savePrefs();
      try {
        await _service.start(
          serverAddr: _serverCtrl.text.trim(),
          authKey: _keyCtrl.text.trim(),
          localPort: int.tryParse(_portCtrl.text.trim()) ?? 5555,
        );
      } catch (_) {}
      setState(() => _loading = false);
    }
  }

  Color _statusColor() {
    return switch (_status) {
      TunnelStatus.connected => Colors.green,
      TunnelStatus.connecting => Colors.orange,
      TunnelStatus.error => Colors.red,
      _ => Colors.grey,
    };
  }

  String _statusText() {
    if (_statusMsg != null && _statusMsg!.isNotEmpty) return _statusMsg!;
    return switch (_status) {
      TunnelStatus.connected => '已连接 · ${_service.clientId ?? ""}',
      TunnelStatus.connecting => '连接中...',
      TunnelStatus.error => '错误',
      TunnelStatus.stopped => '已停止',
      TunnelStatus.disconnected => '已断开',
    };
  }

  @override
  void dispose() {
    _sub?.cancel();
    _serverCtrl.dispose();
    _keyCtrl.dispose();
    _portCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final connected = _status == TunnelStatus.connected;

    return Scaffold(
      appBar: AppBar(title: const Text('GoRemote ADB'), centerTitle: true),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          // Status card
          Card(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                children: [
                  Container(
                    width: 64,
                    height: 64,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: _statusColor().withValues(alpha: 0.12),
                    ),
                    child: Icon(
                      connected ? Icons.check_circle : Icons.power_settings_new,
                      color: _statusColor(),
                      size: 32,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(_statusText(),
                      style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                          color: _statusColor())),
                  if (connected) ...[
                    const SizedBox(height: 8),
                    Text('公网端口: 创建隧道后显示',
                        style: TextStyle(
                            fontSize: 13, color: Colors.grey.shade600)),
                    const SizedBox(height: 4),
                    Text('adb connect your-server:{port}',
                        style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                            color: Colors.blue)),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Config
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('服务器地址',
                      style: TextStyle(
                          fontSize: 12, color: Colors.grey.shade600)),
                  const SizedBox(height: 4),
                  TextField(
                    controller: _serverCtrl,
                    decoration:
                        const InputDecoration(hintText: 'your-server:8080'),
                  ),
                  const SizedBox(height: 12),
                  Text('认证密钥',
                      style: TextStyle(
                          fontSize: 12, color: Colors.grey.shade600)),
                  const SizedBox(height: 4),
                  TextField(
                    controller: _keyCtrl,
                    obscureText: true,
                    decoration:
                        const InputDecoration(hintText: 'auth key'),
                  ),
                  const SizedBox(height: 12),
                  Text('ADB 本地端口',
                      style: TextStyle(
                          fontSize: 12, color: Colors.grey.shade600)),
                  const SizedBox(height: 4),
                  TextField(
                    controller: _portCtrl,
                    keyboardType: TextInputType.number,
                    decoration:
                        const InputDecoration(hintText: '5555'),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 20),

          // Action button
          SizedBox(
            height: 52,
            child: FilledButton.icon(
              onPressed: _loading ? null : _toggle,
              icon: Icon(
                  connected ? Icons.stop : Icons.play_arrow),
              label: Text(
                  connected ? '断开连接' : '启动隧道'),
            ),
          ),
        ],
      ),
    );
  }
}
