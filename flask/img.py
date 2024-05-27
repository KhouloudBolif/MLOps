from flask import Flask, request, jsonify
import cv2
import numpy as np
import pickle
import os
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)

# Charger le modèle pré-entraîné
with open('rf_classifier_model.pkl', 'rb') as f:
    model = pickle.load(f)



# Fonction pour charger les données
def load_data(dataset_dir):
    images = []
    labels = []
    for malware_type in os.listdir(dataset_dir):
        malware_type_dir = os.path.join(dataset_dir, malware_type)
        for image_name in os.listdir(malware_type_dir):
            image_path = os.path.join(malware_type_dir, image_name)
            image = cv2.imread(image_path)
            if image is not None:
                images.append(image)
                labels.append(malware_type)
    return images, labels
# Charger l'encodeur de labels
label_encoder = LabelEncoder()
dataset_dir = 'C:/Users/bnima/Downloads/archive/malware_dataset/train'
_, labels = load_data(dataset_dir)
label_encoder.fit(labels)
# Fonction pour appliquer les filtres de Gabor et extraire les caractéristiques
def gabor_features(image):
    gabor_kernels = []
    ksize = 31  # Taille du noyau
    for theta in np.arange(0, np.pi, np.pi / 4):  # Orientation du noyau
        for sigma in (1, 3):  # Écart-type du noyau
            for lamda in np.arange(np.pi / 4, np.pi, np.pi / 4):  # Longueur d'onde
                kernel = cv2.getGaborKernel((ksize, ksize), sigma, theta, lamda, 0.5, 0, ktype=cv2.CV_32F)
                gabor_kernels.append(kernel)
                
    features = []
    for kernel in gabor_kernels:
        filtered_img = cv2.filter2D(image, cv2.CV_8UC3, kernel)
        mean = filtered_img.mean()
        variance = filtered_img.var()
        features.extend([mean, variance])
    return features

# Fonction pour charger, redimensionner, normaliser et convertir en niveaux de gris une image
def preprocess_image(image_path, target_size=(100, 100)):
    image = cv2.imread(image_path)
    resized_image = cv2.resize(image, target_size)
    normalized_image = resized_image.astype(np.float32) / 255.0
    grayscale_image = cv2.cvtColor(normalized_image, cv2.COLOR_BGR2GRAY)
    return grayscale_image

@app.route('/predict', methods=['POST'])
def predict():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    if file:
        file_path = './uploaded_image.png'
        file.save(file_path)

        # Prétraiter l'image
        grayscale_image = preprocess_image(file_path)
        features = gabor_features(grayscale_image)
        features = np.array(features).reshape(1, -1)
        
        # Faire la prédiction
        prediction = model.predict(features)
        predicted_label = label_encoder.inverse_transform(prediction)
        
        return jsonify({'predicted_label': predicted_label[0]})

if __name__ == '__main__':
    app.run(debug=True)
