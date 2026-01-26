# 🐳 Docker Setup Guide for VulnX Scanner

This guide provides step-by-step instructions for running VulnX Scanner using Docker.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Docker Engine** (version 20.10 or higher)
  - [Install Docker on Linux](https://docs.docker.com/engine/install/)
  - [Install Docker Desktop on Windows](https://docs.docker.com/desktop/install/windows-install/)
  - [Install Docker Desktop on macOS](https://docs.docker.com/desktop/install/mac-install/)
  
- **Docker Compose** (version 2.0 or higher)
  - Included with Docker Desktop
  - [Install Docker Compose on Linux](https://docs.docker.com/compose/install/)

Verify your installation:
```bash
docker --version
docker-compose --version
```

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/shubhushubhu99/vulnXscanner.git
cd vulnXscanner
```

### 2. Configure Environment Variables

Copy the example environment file and configure it:

```bash
cp .env.example .env
```

Edit `.env` and add your **Google Gemini API Key**:

```env
GEMINI_API_KEY=your-actual-api-key-here
FLASK_SECRET_KEY=generate-a-random-secret-key
```

**How to get a Gemini API Key:**
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the key and paste it in your `.env` file

### 3. Build and Run with Docker Compose

**Option A: Using Docker Compose (Recommended)**

```bash
# Build and start the application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```

**Option B: Using Docker CLI**

```bash
# Build the image
docker build -t vulnxscanner:latest .

# Run the container
docker run -d \
  --name vulnxscanner \
  -p 8000:8000 \
  -e GEMINI_API_KEY=your-api-key \
  -e FLASK_SECRET_KEY=your-secret-key \
  -v $(pwd)/data:/app/data \
  vulnxscanner:latest

# View logs
docker logs -f vulnxscanner

# Stop the container
docker stop vulnxscanner
docker rm vulnxscanner
```

### 4. Access the Application

Open your browser and navigate to:

```
http://localhost:8000
```

## 📦 Docker Configuration Details

### Dockerfile Features

The Dockerfile includes several production-ready features:

- **Multi-stage build**: Reduces final image size
- **Non-root user**: Runs as user `vulnx` for security
- **Optimized layers**: Better caching for faster rebuilds
- **Health checks**: Automatic container health monitoring
- **Security hardening**: Minimal attack surface

### Docker Compose Features

The `docker-compose.yml` includes:

- **Environment variables**: Easy configuration management
- **Volume persistence**: Scan history and data survive container restarts
- **Health checks**: Automatic service monitoring
- **Resource limits**: CPU and memory constraints
- **Network isolation**: Secure container networking
- **Auto-restart policy**: Ensures high availability

## 🔧 Advanced Usage

### Development Mode

For development with live code reloading:

```bash
# Create a docker-compose.dev.yml file for development
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
```

### Custom Port

To run on a different port:

```bash
# Edit docker-compose.yml or use environment variable
docker-compose up -d
# OR
docker run -p 9000:8000 vulnxscanner:latest
```

### View Application Logs

```bash
# Follow logs in real-time
docker-compose logs -f vulnxscanner

# View last 100 lines
docker-compose logs --tail=100 vulnxscanner
```

### Execute Commands Inside Container

```bash
# Open a shell in the running container
docker-compose exec vulnxscanner /bin/bash

# Run a one-off command
docker-compose exec vulnxscanner python -c "print('Hello from container')"
```

### Rebuild After Code Changes

```bash
# Rebuild and restart
docker-compose up -d --build

# Force rebuild without cache
docker-compose build --no-cache
docker-compose up -d
```

## 🗄️ Data Persistence

### Volume Mounts

The following data is persisted:

- **Scan History**: `/app/scan_history.json`
- **Messages**: `/app/messages.json`
- **Additional Data**: `/app/data/`

To backup your data:

```bash
# Create backup directory
mkdir -p backups

# Copy data from container
docker cp vulnxscanner:/app/scan_history.json backups/
docker cp vulnxscanner:/app/messages.json backups/
```

## 🔒 Security Best Practices

### 1. Protect Your API Keys

Never commit `.env` files to version control:

```bash
# Ensure .env is in .gitignore
echo ".env" >> .gitignore
```

### 2. Use Strong Secret Keys

Generate a secure Flask secret key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Run with Limited Privileges

The container runs as a non-root user (`vulnx`) by default.

### 4. Resource Limits

Resource limits are configured in `docker-compose.yml`:
- Max CPU: 2 cores
- Max Memory: 2GB

Adjust these based on your system:

```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 1G
```

## 🐛 Troubleshooting

### Container Won't Start

```bash
# Check container status
docker-compose ps

# View detailed logs
docker-compose logs vulnxscanner

# Check health status
docker inspect vulnxscanner | grep -A 10 Health
```

### Port Already in Use

```bash
# Stop conflicting service
sudo lsof -i :8000
sudo kill -9 <PID>

# OR change port in docker-compose.yml
ports:
  - "9000:8000"
```

### Permission Errors

```bash
# Fix volume permissions
sudo chown -R $(id -u):$(id -g) data/
```

### API Key Not Working

Ensure your `.env` file contains:
```env
GEMINI_API_KEY=your-actual-key-here
```

Restart the container:
```bash
docker-compose down
docker-compose up -d
```

## 🧹 Cleanup

### Remove Containers and Images

```bash
# Stop and remove containers
docker-compose down

# Remove containers, networks, and volumes
docker-compose down -v

# Remove image
docker rmi vulnxscanner:latest

# Clean up all unused Docker resources
docker system prune -a --volumes
```

## 📊 Monitoring

### Check Container Health

```bash
# View health status
docker inspect --format='{{json .State.Health}}' vulnxscanner | jq

# View resource usage
docker stats vulnxscanner
```

### Health Check Endpoint

The application includes a built-in health check that runs every 30 seconds:

```bash
curl http://localhost:8000/
```

## 🔄 Update Strategy

### Updating the Application

```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

## 💡 Tips

1. **Use .env for configuration**: Never hardcode secrets
2. **Persist important data**: Use volumes for scan history
3. **Monitor resources**: Check `docker stats` regularly
4. **Keep images updated**: Rebuild periodically for security patches
5. **Backup data**: Regularly backup scan history and configurations

## 📝 Environment Variables Reference

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `GEMINI_API_KEY` | Google Gemini API key for AI analysis | Yes | - |
| `FLASK_SECRET_KEY` | Secret key for Flask sessions | Recommended | Generated |
| `FLASK_ENV` | Flask environment (production/development) | No | production |
| `LOG_LEVEL` | Logging level (debug/info/warning/error) | No | info |
| `PYTHONUNBUFFERED` | Disable Python output buffering | No | 1 |

## 🆘 Getting Help

If you encounter issues:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review application logs: `docker-compose logs -f`
3. Open an issue on [GitHub](https://github.com/shubhushubhu99/vulnXscanner/issues)
4. Ensure your Docker version is up to date

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [VulnX Scanner GitHub](https://github.com/shubhushubhu99/vulnXscanner)
- [Google Gemini API](https://ai.google.dev/)

---

**Note**: This Docker setup is optional and does not affect existing workflows. You can still run the application directly with Python if preferred.
