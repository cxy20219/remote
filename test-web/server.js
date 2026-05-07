const http = require('http');
const fs = require('fs');
const path = require('path');

const server = http.createServer((req, res) => {
    let filePath = req.url === '/' ? 'test-web/index.html' : path.join('test-web', req.url.slice(1));
    try {
        const content = fs.readFileSync(filePath);
        const ext = path.extname(filePath);
        const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript' };
        res.writeHead(200, { 'Content-Type': mime[ext] || 'text/plain' });
        res.end(content);
    } catch (e) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

server.listen(7777, '127.0.0.1', () => console.log('WEB_READY on 7777'));
