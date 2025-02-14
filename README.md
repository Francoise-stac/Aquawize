docker build --build-arg BRANCH=dev-RESTFUL -f "installation_Deployment/Dockerfile" -t aquawize_api_img:latest . --no-cache


docker run -it -d -v /var/run/docker.sock:/var/run/docker.sock --env-file .env --name aquawize_core aquawize_api_img:latest
