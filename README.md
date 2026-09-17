# 本机端口控制台

这是一个只监听 127.0.0.1 的 Windows 本机“项目端口台”，负责：

- 主页面只显示已经登记的项目端口，不再展示 Windows 和软件产生的大量内部端口；
- 同一项目端口的 IPv4、IPv6、多进程重复绑定会合并成一个入口；
- 用项目名称和用途说明替代难懂的系统进程描述；
- 区分“仅本机”“所有网卡”“指定网卡”；
- 自动识别常见服务，并为可能的 HTTP 服务生成访问入口；
- 扫描已登记项目，在网页中安全启动或停止；
- 兼容普通命令、Windows 服务和 Docker Compose 项目；
- **智能运行时端口自适应**：服务端口变动后无需手动改配置，控制台自动捕获实际端口并更新链接；
- **失效项目自动软归档**：路径失效、无入口、无进程的服务自动折叠到已归档区，不污染活动端口表与卡片。

## 启动

首次安装依赖：python -m pip install -r requirements.txt。进程归属核对使用 psutil，本机运行环境需安装。

在项目根目录下，于 PowerShell 中执行：

`powershell
.\start.ps1
`

脚本会在后台隐藏启动服务，并自动调用系统浏览器打开：

`	ext
http://127.0.0.1:8787
`

停止控制台：

`powershell
.\stop.ps1
`

也可以在项目目录直接前台运行调试：

`powershell
python server.py
`

## 多电脑迁移与复用

在其他电脑上快速部署运行：

1. **克隆仓库**：
   `powershell
   git clone https://github.com/2392772541/port-console.git
   cd port-console
   `
2. **安装依赖**：
   `powershell
   python -m pip install -r requirements.txt
   `
3. **配置项目**：
   - 仓库内已内置工作台自管理服务（port-atlas）。
   - 可参考 config/projects.example.json，在 config/projects.json 中配置新电脑上的本机项目路径与端口；
   - 也可以将已有项目的根目录放到工作台上一级目录，并在项目根目录放置 port-console.project.json，控制台会自动扫描并注册。
   - 若保留原有配置，在新电脑上不存在的项目会被自动识别并归入“已归档项目”，不影响控制台启动。
4. **启动服务**：
   `powershell
   .\start.ps1
   `

## 登记未来项目

新项目需要在项目根目录放置下面的清单。端口台会自动发现它，并在项目停止后仍保留名称、用途和启动按钮：

`	ext
port-console.project.json
`

普通 Python/Node/Go 项目示例：

`json
{
  "id": "my-api",
  "name": "我的 API",
  "description": "本机开发接口",
  "type": "command",
  "working_directory": ".",
  "command": ["python", "app.py"],
  "expected_ports": [8000],
  "url": "http://127.0.0.1:8000",
  "enabled": true,
  "allow_stop": true,
  "tags": ["Python", "API"]
}
`

command 必须是字符串数组。网页只提交项目 ID，不能传入任意命令；真正的启动命令只从本地清单读取。

仓库内提供了三个模板：

- project-manifest.example.json：普通本机项目；
- docker-project.example.json：Docker Compose 项目；
- process-compose-project.example.json：Process Compose 项目。

默认扫描根目录配置在 config/projects.json 的 scan_roots 中。扫描深度为四层，并会跳过 .git、
ode_modules、虚拟环境和构建目录。

## 项目类型

### command

使用固定的可执行文件和参数启动。llow_stop=true 时，优先运行配置的 stop_command；普通项目支持重新识别端口上的进程，并核对其工作目录位于项目目录内，因此在别处启动或重启工作台后也能停止。目录不符、系统服务和工作台自身不会按普通进程结束。

### windows-service

示例：

`json
{
  "id": "mysql-service",
  "name": "MySQL 服务",
  "type": "windows-service",
  "working_directory": ".",
  "service_name": "mysql",
  "expected_ports": [3306],
  "enabled": true,
  "allow_stop": false
}
`

启动系统服务可能需要管理员权限，失败信息会显示在网页中。

### docker-compose

使用固定命令 docker compose -f <compose_file> up -d 启动，停止时使用 docker compose stop。浏览器不能改变 Compose 路径或参数。

## 安全边界

- 服务只绑定 127.0.0.1；
- 不提供 CORS，不接受远程客户端；
- 启停请求需要页面运行时令牌；
- 不允许网页提交任意命令、程序路径或参数；
- 项目 ID、服务名、端口和路径都在服务端校验；
- 停止普通进程前核对端口和项目目录，使用进程创建时间防止 PID 被复用；停止后检查端口确实关闭，否则返回失败原因；
- 所有操作写入 logs/actions.log。

## 测试

`powershell
python -m unittest discover -s tests -v
`
