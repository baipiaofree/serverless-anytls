# Serverless AnyTLS

基于 serverless 实现的 AnyTLS (udp over tcp) 代理服务器

## 环境变量
- `PORT`: 服务器监听端口
- `PASSWORD`: 认证密码

## 安装

### 配置环境变量

编辑 `anytls.js` 文件顶部的修改环境变量:

```javascript
const PORT = 8443;              // 服务器监听端口
const PASSWORD = '0a6568ff-ea3c-4271-9020-450560e10d63';  // 认证密码
```
### 安装依赖
```bash
npm install
```

### 运行服务

```bash
node anytls.js
```
或者:

```bash
npm start
```

## 客户端连接

V2rayN,Shadowrocket,Mihomo,sing-box


## 许可

GPL-3.0