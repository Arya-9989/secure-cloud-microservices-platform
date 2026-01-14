# Secure Cloud-Native Microservices Platform

A production-oriented cloud-native microservices platform demonstrating secure authentication, CI/CD automation, and containerized deployment.

## 🔧 Tech Stack
- Backend: Python (Django REST Framework)
- CI/CD: Jenkins
- Containers: Docker
- Version Control: Git, GitHub
- Cloud-Ready Architecture
- Security: JWT-based authentication

## 🚀 Features
- Secure authentication microservice
- Dockerized microservice architecture
- Jenkins CI/CD pipeline for automated build and deployment
- GitHub-integrated version control
- Designed for cloud deployment (AWS/GCP/Azure ready)

## 🔄 CI/CD Workflow
1. Code pushed to GitHub
2. Jenkins pulls latest code
3. Docker image is built automatically
4. Container is deployed locally

📌 Project Purpose

Built to demonstrate real-world DevOps, cloud, and security practices for entry-level IT roles.

👤 Author

Arya Mahindrakar

## ▶️ How to Run Locally
```bash
docker build -t auth-service auth-service-python
docker run -p 8000:8000 auth-service

