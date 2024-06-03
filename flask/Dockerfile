FROM python

# Install dependencies
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libglib2.0-0

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install -r requirements.txt

# Copy the application code and model file
COPY . .

COPY Models/rf_classifier_model.pkl /app/flask/Models/
COPY Models/random_forest_model.pkl /app/flask/Models/
COPY Dataset/train /app/flask/Dataset/train
# Command to run the application
CMD ["python", "app.py"]
