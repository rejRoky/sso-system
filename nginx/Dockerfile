# nginx/Dockerfile

# Use the official Nginx image from the Docker Hub as a base image
FROM nginx:latest

# Remove default configuration
RUN rm /etc/nginx/conf.d/default.conf

# Copy your custom Nginx configuration file into the container
COPY nginx.conf /etc/nginx/nginx.conf

# Expose port 80
EXPOSE 80
