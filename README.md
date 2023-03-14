## Requirements

- Docker
- ORAS CLI
- Notation CLI
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

3. Add `localhost:5000` to the list of insecure registries
   For Mac: 
   ```
   echo '{"insecureRegistries": ["localhost:5000"]}' > /Users/$USER/Library/Application\ Support/notation/config.json
   ```

   For Linux:
   ```
   echo '{"insecureRegistries": ["localhost:5000"]}' > ~/.config/notation/config.json
   ```

4. Build the image and push it to the CNCF container registory
   ```
   docker build -t $IMAGE https://github.com/wabbit-networks/net-monitor.git#main
   docker push $IMAGE
   ```

5. Generate key and certificate to sign the image
   ```
   notation cert generate-test --default "wabbit-networks.io"
   ```

6. Sign the image
   ```
   notation sign $IMAGE
   ```

7. List the referrers of a manifest in the remote registry
   ```
   oras discover -o tree $IMAGE
   ```