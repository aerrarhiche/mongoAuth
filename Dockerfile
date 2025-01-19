# Use an official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Set environment variables
ENV FLASK_APP=run.py
ENV FLASK_ENV=production
ENV PORT=8080

# Expose the correct port
EXPOSE 8080

# Run the Flask application
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=8080"]