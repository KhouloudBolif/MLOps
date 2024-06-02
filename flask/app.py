from flask import Flask, render_template, request, redirect, url_for, flash
import os
from PIL import Image
from werkzeug.utils import secure_filename
import pickle
import numpy as np
import cv2
from sklearn.preprocessing import LabelEncoder
from processingNewMalware import *


app = Flask(__name__)

model_path = 'C:/Users/linat/Desktop/MLOps-main/MLOps-main/rf_classifier_model.pkl'
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'uploads')



@app.route('/')
def home():
    return render_template('principal.html')

with open(model_path, 'rb') as f :
    model = pickle.load(f)


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

label_encoder = LabelEncoder()
dataset_dir = 'C:/Users/linat/Desktop/malware_dataset/train'
_, labels = load_data(dataset_dir)
label_encoder.fit(labels)



def gabor_features(image):
    gabor_kernels = []
    ksize = 31  # Taille du noyau
    # Ajustement des paramètres pour obtenir 24 noyaux
    selected_thetas = np.linspace(0, np.pi, 6)  # Utiliser 6 orientations
    selected_sigmas = [1, 3]  # Garder les deux écart-types
    selected_lambdas = np.linspace(np.pi / 4, np.pi, 2)  # Garder les deux longueurs d'onde
    
    # Génération des noyaux Gabor
    for theta in selected_thetas:
        for sigma in selected_sigmas:
            for lamda in selected_lambdas:
                kernel = cv2.getGaborKernel((ksize, ksize), sigma, theta, lamda, 0.5, 0, ktype=cv2.CV_32F)
                gabor_kernels.append(kernel)
                
    features = []
    # Extraction de caractéristiques pour chaque noyau
    for kernel in gabor_kernels:
        filtered_img = cv2.filter2D(image, cv2.CV_8UC3, kernel)
        features.append(filtered_img.mean())
        features.append(filtered_img.var())

    # S'assurer d'avoir exactement 48 caractéristiques
    return features[:48]


def preprocess_image(image_path, target_size=(100, 100)):
    image = cv2.imread(image_path)
    resized_image = cv2.resize(image, target_size)
    normalized_image = resized_image.astype(np.float32) / 255.0
    grayscale_image = cv2.cvtColor(normalized_image, cv2.COLOR_BGR2GRAY)
    return grayscale_image


@app.route('/upload2', methods=['GET', 'POST'])
def upload_image():
    error_message = None
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename != '':  # S'assure que le fichier est présent et que le nom n'est pas vide
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return redirect(url_for('display_image', filename=filename))
        else:
            error_message='No file selected'
            return redirect(url_for('upload2_image'))    
    return render_template('upload2.html')

@app.route('/display/<filename>')
def display_image(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    grayscale_image = preprocess_image(filepath)
    features = gabor_features(grayscale_image)
    prediction = model.predict([features])
    predicted_label = label_encoder.inverse_transform(prediction)
    return render_template('display.html', filename=filename, predicted_class=predicted_label[0])

##partie signature
file_path = 'C:/Users/linat/Desktop/MLOps-main/lieaugit/MLOps/flask/eclipsec.exe'
@app.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    error_message = None
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            return redirect(url_for('file_analysis', filename=filename))
        else:
            error_message = 'No file selected'
            return redirect(url_for('upload_file'))
    return render_template('upload.html')
    
@app.route('/analysis/<filename>')
def file_analysis(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    features = Extract_File(file_path)
    if features:
        predictions = make_prediction(features)
        predictions_with_indices = list(enumerate(predictions))
        return render_template('analysis.html', predictions_with_indices=predictions_with_indices)
    else:
        return render_template('analysis.html', error="Aucune caractéristique extraite. Impossible de faire une prédiction.")


def make_prediction(features):
    model = Load_model('C:/Users/linat/Desktop/MLOps-main/MLOps-main/random_forest_model.pkl')
    # Transformer les caractéristiques d'un dictionnaire en liste
    feature_list = list(features.values()) if isinstance(features, dict) else features
    # S'assurer que les caractéristiques sont sous forme d'une liste de listes (2D array)
    return model.predict([feature_list])

def Load_model(model_path):
    import pickle
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    return model
        

if __name__ == '__main__':
    app.run(debug=True)

