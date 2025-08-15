#!/bin/bash

# Build and Deploy HarborSeal API to Kubernetes

set -e

echo "🚀 Building HarborSeal API Docker image..."

# Build the Docker image
docker build -t harborseal-api:latest .

echo "✅ Docker image built successfully"

echo "🔧 Deploying MongoDB to Kubernetes..."

# Deploy MongoDB first
kubectl apply -f k8s-mongodb.yaml

# Wait for MongoDB to be ready
echo "⏳ Waiting for MongoDB to be ready..."
kubectl wait --for=condition=ready pod -l app=mongodb --timeout=300s

echo "🔧 Deploying HarborSeal API to Kubernetes..."

# Deploy the API
kubectl apply -f k8s-deployment.yaml

# Wait for deployment to be ready
echo "⏳ Waiting for HarborSeal API to be ready..."
kubectl wait --for=condition=ready pod -l app=harborseal-api --timeout=300s

echo "✅ Deployment complete!"

# Show service information
echo "📋 Service information:"
kubectl get services harborseal-api-service

echo ""
echo "🎉 HarborSeal API is now running!"
echo ""
echo "To access the API:"
echo "1. Get the external IP: kubectl get service harborseal-api-service"
echo "2. Access the API at: http://<EXTERNAL-IP>/health"
echo ""
echo "To view logs:"
echo "kubectl logs -l app=harborseal-api -f"
echo ""
echo "To update the deployment:"
echo "./build-and-deploy.sh"