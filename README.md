🚀 Secure Cloud-Native Microservices Platform

A production-oriented cloud-native microservices project focused on secure authentication, CI/CD automation, and containerized deployment, built to reflect real-world DevOps and cloud engineering practices.

This project demonstrates how modern backend services are developed, automated, and deployed using industry-standard tools.

📌 Key Highlights

Secure authentication service using JWT

Fully Dockerized microservice

Jenkins CI/CD pipeline integrated with GitHub

Automated build and deployment workflow

Designed with cloud-ready architecture principles

🛠️ Tech Stack
Backend

Python

Django REST Framework

JWT-based Authentication

DevOps & Automation

Jenkins (CI/CD Pipelines)

Docker (Containerization)

Version Control

Git

GitHub

Cloud & Architecture

Cloud-ready design (AWS / Azure / GCP compatible)

Microservices-oriented structure

⚙️ Architecture Overview
Developer → GitHub → Jenkins CI Pipeline → Docker Build → Container Deployment


Code changes are pushed to GitHub

Jenkins automatically pulls the latest code

Docker image is built inside the pipeline

Container is deployed automatically

🔄 CI/CD Workflow

Developer pushes code to GitHub

Jenkins Pipeline is triggered

Jenkins builds the Docker image

Container is deployed automatically

Service becomes available on the configured port

🚀 Features

Secure authentication microservice

Token-based access control (JWT)

Automated CI/CD using Jenkins

Dockerized build and runtime environment

GitHub-integrated development workflow

Cloud-deployment ready architecture

▶️ Run Locally
Prerequisites

Docker

Git

Steps
# Build Docker image
docker build -t auth-service auth-service-python

# Run the container
docker run -p 8000:8000 auth-service


Access the service at:

http://localhost:8000

🎯 Project Purpose

This project was built to demonstrate real-world DevOps, cloud, and security workflows for:

Entry-level Cloud Engineer roles

DevOps Engineer (Fresher) roles

Backend / Platform Engineering roles

It focuses on practical implementation, not just theory.

👤 Author

Arya Mahindrakar

B.Tech — Cloud Technology & Information Security

🔗 GitHub: https://github.com/Arya-9989

📈 What This Project Demonstrates

End-to-end CI/CD pipeline implementation

Real Docker + Jenkins integration on Windows

Secure backend service development

Industry-standard DevOps workflow understanding
