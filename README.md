# Phishing-detection-# 🛡️ Phishing Detector - Production Ready

A production-ready Flask application for detecting phishing websites with advanced URL analysis.

## 🚀 Features

- **Comprehensive URL Analysis**: 10+ security checks
- **Production-Ready**: Configured for Render deployment
- **Logging**: Rotating file logs for monitoring
- **Error Handling**: Robust error handling and validation
- **CORS Enabled**: API accessible from any origin
- **Health Check**: `/health` endpoint for monitoring
- **Rate Limiting Ready**: Request size limits configured

## 📋 Security Checks

1. ✅ HTTPS Protocol Verification
2. 🔍 Suspicious TLD Detection
3. 🌐 IP Address Usage Check
4. 📊 Subdomain Analysis
5. 🔤 Keyword Pattern Matching
6. 📏 URL Length Analysis
7. ⚡ Special Character Detection
8. 🎭 Homograph Attack Detection
9. 🔄 Typosquatting Detection
10. 🔌 Unusual Port Detection

## 🛠️ Local Development

### Prerequisites
- Python 3.11+
- pip



Visit `http://localhost:5000` in your browser.

## 📦 Project Structure

```
phishing-detector/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── runtime.txt           # Python version for Render
├── render.yaml           # Render deployment config
├── .gitignore            # Git ignore file
├── templates/
│   └── index.html        # Frontend UI
├── logs/                 # Application logs (auto-created)
└── README.md            # This file
```

## 🌐 Deploy to Render

### Option 1: Using render.yaml (Recommended)

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin <your-github-repo>
   git push -u origin main
   ```

2. **Deploy on Render**
   - Go to [Render Dashboard](https://dashboard.render.com/)
   - Click "New +"
   - Select "Blueprint"
   - Connect your GitHub repository
   - Render will automatically detect `render.yaml` and configure everything

### Option 2: Manual Setup

1. **Create Web Service on Render**
   - Go to [Render Dashboard](https://dashboard.render.com/)
   - Click "New +" → "Web Service"
   - Connect your GitHub repository

2. **Configure Settings**
   - **Name**: `phishing-detector`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn --bind 0.0.0.0:$PORT --workers 4 --threads 2 --timeout 120 app:app`
   - **Instance Type**: Free (or choose paid for better performance)

3. **Environment Variables** (Optional)
   - `PYTHON_VERSION`: `3.11.0`
   - `FLASK_ENV`: `production`

4. **Deploy**
   - Click "Create Web Service"
   - Wait for deployment to complete

## 🔧 Configuration

### Gunicorn Configuration (Production)

The app uses Gunicorn with the following settings:
- **Workers**: 4 (adjust based on CPU cores)
- **Threads**: 2 per worker
- **Timeout**: 120 seconds
- **Binding**: 0.0.0.0:$PORT

### Logging

Logs are stored in the `logs/` directory:
- **File**: `phishing_detector.log`
- **Max Size**: 10KB per file
- **Backups**: 10 files
- **Level**: INFO

## 📊 API Endpoints

### POST /scan
Analyze a URL for phishing indicators.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "risk_score": 3,
  "is_phishing": false,
  "checks": {
    "url_pattern": {
      "passed": true,
      "reasons": ["Using secure HTTPS protocol", "Normal domain structure"]
    }
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### GET /health
Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## 🔒 Security Features

- **Input Validation**: URL length and format validation
- **Request Size Limit**: Max 16KB per request
- **Error Handling**: Comprehensive error catching and logging
- **CORS Protection**: Configurable origins
- **Rate Limiting Ready**: Easy to add with Flask-Limiter

## 📈 Performance Optimization

- Uses Gunicorn for production serving
- Multiple workers for concurrent requests
- Thread-based parallelism
- Efficient regex patterns
- Minimal external dependencies

## 🧪 Testing

Test the API using curl:

```bash
# Local testing
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://suspicious-site.tk"}'

# Production testing (replace with your Render URL)
curl -X POST https://your-app.onrender.com/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://suspicious-site.tk"}'
```

## 🐛 Troubleshooting

### Issue: App not starting on Render
- Check logs in Render dashboard
- Verify `requirements.txt` has all dependencies
- Ensure Python version matches `runtime.txt`

### Issue: High response times
- Increase Gunicorn workers
- Upgrade to paid Render instance
- Add caching layer (Redis)

### Issue: Logs not appearing
- Check `logs/` directory exists
- Verify file permissions
- Review Render logs in dashboard

## 🚀 Future Enhancements

- [ ] Add Redis caching for repeated URL checks
- [ ] Implement rate limiting with Flask-Limiter
- [ ] Add database for scan history
- [ ] Integrate real-time threat intelligence APIs
- [ ] Add email/Slack notifications
- [ ] Implement user authentication
- [ ] Create admin dashboard

## 📝 License

MIT License - Feel free to use and modify!

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📧 Support

For issues and questions, please open a GitHub issue.

---

**Built with ❤️ using Flask and deployed on Render**
