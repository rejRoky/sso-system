# Use the official Redis image from Docker Hub
FROM redis:latest

# Copy the custom Redis configuration file into the container
COPY redis.conf /usr/local/etc/redis/redis.conf

# Expose the default Redis port
EXPOSE 6379

# Start Redis with the custom configuration
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]
