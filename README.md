# Trojan 多服务器管理端使用说明（中文）

## 1. 项目简介
这是一个基于 Flask 的 Trojan 管理面板，支持：

- 多服务器配置管理（独立页面维护，保存到 `servers.json`）
- 单台服务器端口切换（执行 `ssh xxx trojan port $1`）
- 单台检查 Trojan 服务运行状态（执行 `trojan status`）
- 可选登录鉴权（账号密码保存到 `servers.json`）
- 可选手机号验证码登录（阿里云短信，手机号白名单配置在 `servers.json`）
- Trojan 订阅地址生成（单选/多选服务器，返回 trojan 链接 base64）

## 2. 环境要求

- Python 3.10+
- `uv`（推荐）
- 可用的 SSH 连接（本机到各服务器）

## 3. 快速开始

在项目目录执行：

```bash
cd /Users/shafish/Project/Python/tj
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
```

创建配置文件：

```bash
cp servers.example.json servers.json
```

启动服务：

```bash
TROJAN_PANEL_HOST=127.0.0.1 TROJAN_PANEL_PORT=8000 .venv/bin/python app.py
```

浏览器访问：

- 操作页：[http://127.0.0.1:8000](http://127.0.0.1:8000)
- 服务器管理页：[http://127.0.0.1:8000/servers](http://127.0.0.1:8000/servers)
- 登录页：[http://127.0.0.1:8000/login](http://127.0.0.1:8000/login)

## 4. 配置文件说明（servers.json）

顶层结构：

```json
{
  "auth": {
    "username": "admin",
    "password": "change-me"
  },
  "sms_login": {
    "enabled": true,
    "allowed_phones": [
      "13800138000"
    ],
    "access_key_id": "LTAIxxxxxxxx",
    "access_key_secret": "xxxxxxxx",
    "sign_name": "速通互联验证码",
    "template_code": "100001",
    "template_param": "{\"code\":\"##code##\",\"min\":\"##min##\"}"
  },
  "subscriptions": {},
  "servers": []
}
```

每个服务器支持字段：

- `id`：唯一标识，必填
- `name`：显示名称，建议填写
- `description`：备注，可选
- `addr`：对外检测地址（域名或 IP），用于网络可达性探测
- `trojan_password`：该服务器的 Trojan 密码（用于生成订阅链接）
- `current_port`：当前使用端口，可选（建议填写）
- `command_template`：端口切换命令模板，必填，必须包含 `$1`
- `status_command_template`：状态检查命令，可选（不填则自动从 `command_template` 推导）

顶层 `auth` 字段说明：

- `auth.username`：登录账号
- `auth.password`：登录密码
- 两个都为空或未设置：关闭登录校验
- 两个都填写：启用登录校验（访问页面与 API 都需要先登录）

顶层 `sms_login` 字段说明（可选）：

- `sms_login.enabled`：是否启用手机号验证码登录
- `sms_login.allowed_phones`：允许登录的手机号白名单，仅支持列表中的号码
- `sms_login.access_key_id` / `sms_login.access_key_secret`：阿里云 AK/SK（也可用环境变量 `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET`）
- `sms_login.sign_name`：阿里云短信签名（对应 sms-demo `sign_name`）
- `sms_login.template_code`：阿里云模板编号（对应 sms-demo `template_code`）
- `sms_login.template_param`：模板参数字符串（对应 sms-demo `template_param`，会把 `##code##` 替换为真实验证码，把 `##min##` 替换为有效分钟数）
- 验证码默认有效期 15 分钟
- 每个手机号每天最多发送 2 次验证码；两次验证码均未通过后，当天仅可使用账号密码登录

顶层 `subscriptions` 字段说明：

- 由系统自动维护，记录订阅信息
- 兼容两种结构：`token -> server_ids`（旧格式）和 `token -> { server_ids, expires_at }`（新格式）
- `expires_at` 为可选 ISO 时间，表示订阅链接有效期截止时间；为空表示永久有效
- 你可以不手工修改

说明：快捷端口不再通过配置指定，系统会根据 `current_port` 自动生成 `current_port + 1`。

示例：

```json
{
  "servers": [
    {
      "id": "hk-main",
      "name": "Hong Kong Main",
      "description": "主节点",
      "addr": "tj9.tffats.top",
      "current_port": 443,
      "command_template": "ssh -i ~/.ssh/id_ed25519 root@203.0.113.10 trojan port $1",
      "status_command_template": "ssh -i ~/.ssh/id_ed25519 root@203.0.113.10 trojan status"
    }
  ]
}
```

## 5. 页面功能使用

### 5.1 服务器管理

- 访问 `/servers` 页面
- 点击“新增服务器”添加节点
- 编辑 `名称/描述`
- `ID` 会自动生成，页面中为只读显示
- `命令模板` 与 `状态命令` 会根据 `ID` 自动生成，页面中为只读显示
- `当前端口/检测地址/Trojan 密码` 在页面中为只读显示
- 可在“登录配置”里设置账号和密码
- 点击“保存配置”写入 `servers.json`
- 保存成功后页面会自动刷新

注意：

- 自动生成的 `command_template` 形如 `ssh <id> trojan port $1`
- 自动生成的 `status_command_template` 形如 `ssh <id> trojan status`
- 若你需要修改 `ID/命令模板/状态命令/当前端口/检测地址/Trojan 密码`，请手工编辑 `servers.json`
- `id` 不能重复

### 5.2 单台端口切换

- 在服务器卡片输入端口
- 点击“切换端口”
- 面板会显示命令、返回码、stdout、stderr
- 切换成功后会自动把新端口回写到 `servers.json` 的 `current_port`

### 5.3 服务状态检查

- 单台：点击卡片“检查状态”
- 系统会执行 `trojan status` 并解析 `Active:` 行
- 若包含 `active (running)`，判定为运行正常
- 根据配置里的 `current_port` 自动生成快捷端口按钮：`当前端口 + 1`

### 5.4 网络连通性检测

- 在操作页点击“检测网络”
- 系统会基于 `addr + current_port` 做 TCP 连通性探测
- 可达即显示“可访问”，不可达会显示错误信息（如超时、拒绝连接、DNS 解析失败）

### 5.5 登录与退出

- 开启方式：在 `/servers` 页面“登录配置”同时填写账号和密码并保存
- 关闭方式：把登录账号和密码都清空并保存
- 开启后，未登录访问会自动跳转 `/login`
- 页面右上角可点击“退出登录”
- 如果在 `servers.json` 配置了 `sms_login`，登录页会出现“手机号验证码登录”
- 手机号由用户在登录页手动输入，且必须命中 `sms_login.allowed_phones` 白名单

### 5.6 Trojan 订阅地址（Base64）

- 在操作页每个服务器卡片勾选“订阅”（可单选或多选）
- 可填写“自定义订阅标识”（可选）
- 可选择“永久 / 1天 / 7天 / 30天 / 自定义时间”作为订阅有效期
- 点击页面顶部“生成访问地址”
- 面板会返回一个订阅 URL（形如 `/sub/<token>`）
- 在浏览器或客户端访问该 URL，返回内容为所选服务器 trojan 链接换行后再做 base64 的结果
- 如果自定义订阅标识已存在，会被最新选择覆盖（以最新为准）
- 已过期订阅会返回 `410 Gone`，订阅管理页也会标记为“已过期”

链接格式：

```text
trojan://<trojan_password>@<addr>:<current_port>?security=tls&headerType=none&type=tcp#<name>
```

示例：

```text
trojan://tffats110@tj10.tffats.top:25092?security=tls&headerType=none&type=tcp#tj10
```

注意：如果某台服务器未配置 `addr`、`current_port` 或 `trojan_password`，生成会失败并提示具体缺失字段。

## 6. 部署操作（生产环境）

以下示例以 Ubuntu + systemd + Nginx 为例。

### 6.1 准备目录与环境

```bash
sudo mkdir -p /opt/trojan-panel
sudo chown -R $USER:$USER /opt/trojan-panel
cd /opt/trojan-panel
# 将项目文件放到该目录（git clone 或拷贝）
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
uv pip install --python .venv/bin/python gunicorn
cp servers.example.json servers.json
```

### 6.2 配置环境变量

建议通过 systemd 注入以下变量：

- `TROJAN_PANEL_HOST=127.0.0.1`
- `TROJAN_PANEL_PORT=8000`
- `TROJAN_PANEL_CONFIG=/opt/trojan-panel/servers.json`
- `TROJAN_PANEL_SECRET_KEY=请替换为高强度随机字符串`

`TROJAN_PANEL_SECRET_KEY` 用于 Flask 会话签名，生产环境不要使用默认值。

### 6.3 使用 WSGI 启动（Gunicorn）

先手动验证 WSGI 启动是否正常：

```bash
cd /opt/trojan-panel
TROJAN_PANEL_CONFIG=/opt/trojan-panel/servers.json \
TROJAN_PANEL_SECRET_KEY=replace-with-a-long-random-string \
.venv/bin/gunicorn --workers 2 --threads 4 --bind 127.0.0.1:8000 --timeout 60 app:app
```

说明：

- `app:app` 表示加载 `app.py` 中的 Flask 实例 `app`
- `--workers 2 --threads 4` 为中小规模机器的通用起步值
- 生产环境建议使用 Gunicorn（WSGI），不要直接用 `python app.py`

### 6.4 配置 systemd 自启动（WSGI）

创建服务文件 `/etc/systemd/system/trojan-panel.service`：

```ini
[Unit]
Description=Trojan Panel
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/trojan-panel
Environment=TROJAN_PANEL_CONFIG=/opt/trojan-panel/servers.json
Environment=TROJAN_PANEL_SECRET_KEY=replace-with-a-long-random-string
ExecStart=/opt/trojan-panel/.venv/bin/gunicorn --workers 2 --threads 4 --bind 127.0.0.1:8000 --timeout 60 --access-logfile - --error-logfile - app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now trojan-panel
sudo systemctl status trojan-panel
```

查看日志：

```bash
sudo journalctl -u trojan-panel -f
```

### 6.5 配置 Nginx 反向代理

建议只让面板监听本机 `127.0.0.1:8000`，对外由 Nginx 暴露。

```nginx
server {
    listen 80;
    server_name panel.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

检查并重载：

```bash
sudo nginx -t
sudo systemctl reload nginx
```

如需公网访问，建议配合 HTTPS（例如 `certbot`）并限制来源 IP。

### 6.6 升级发布流程

```bash
cd /opt/trojan-panel
# 更新代码（按你的实际方式）
uv pip install --python .venv/bin/python -r requirements.txt
uv pip install --python .venv/bin/python gunicorn
sudo systemctl restart trojan-panel
sudo systemctl status trojan-panel
```

### 6.7 配置生效说明

- 修改 `servers.json` 后不需要重启服务，页面下一次请求会读取新配置。
- 如果你修改的是 systemd 环境变量或服务文件，则必须执行：

```bash
sudo systemctl daemon-reload
sudo systemctl restart trojan-panel
```

## 7. 常见问题

### 7.1 状态检查失败（SSH 失败）

检查：

- SSH 用户、IP、端口是否正确
- 私钥路径是否正确（例如 `~/.ssh/id_ed25519`）
- 目标机是否允许当前用户执行 `trojan status`

### 7.2 返回 `service: unknown`

表示命令执行成功但输出不符合常见格式，建议：

- 在配置中显式填写 `status_command_template`
- 在服务器上手工执行同一命令确认输出格式

### 7.3 保存配置报错

常见原因：

- `id` 为空或重复
- `command_template` 未包含 `$1`
- `addr` 含空白字符
- `trojan_password` 含空白字符
- `current_port` 不是 1-65535 的整数
- 登录账号和密码只填了一个（必须同时填写或同时留空）

## 8. 安全建议

- 本项目默认是管理面板，请仅在内网或受控环境使用
- 不要暴露到公网
- 使用最小权限 SSH 账号
- 推荐通过防火墙限制访问来源

## 9. 相关文件

- 主程序：`app.py`
- 前端页面：`templates/index.html`、`templates/servers.html`
- 前端逻辑：`static/app.js`
- 样式：`static/style.css`
- 依赖：`requirements.txt`
- 配置示例：`servers.example.json`
