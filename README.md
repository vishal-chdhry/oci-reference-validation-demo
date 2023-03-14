## Requirements

- Docker
- ORAS CLI
- Go 1.19+

## Setup
1. Setup Environment variables
   ```
   export PORT=5000
   export REGISTRY=localhost:${PORT}
   export REPO=${REGISTRY}/lachie/net-monitor
   export IMAGE=${REPO}:v1
   ```
2. Start a local instance of CNCF container registry
   ```
   docker run -d -p ${PORT}:5000 ghcr.io/oras-project/registry:v1.0.0-rc.4
   ```

3. Build the image and push it to the CNCF container registory
   ```
   docker build -t $IMAGE https://github.com/wabbit-networks/net-monitor.git#main
   docker push $IMAGE
   ```