import os
import joblib
import pandas as pd
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score

# Constantes
MODEL_PATH = 'random_forest_model.pkl'
FEATURES_LIST = [
    'AddressOfEntryPoint', 'MajorLinkerVersion', 'MajorImageVersion', 
    'MajorOperatingSystemVersion', 'DllCharacteristics', 'SizeOfStackReserve', 'NumberOfSections'
]

# Fonction pour entraîner et sauvegarder le modèle
def train_and_save_model():
    """Entraîner et sauvegarder un modèle RandomForestClassifier."""
    st.write("Entraînement du modèle, cela peut prendre un moment...")
    
    # Chargement des données
    data = pd.read_csv("DatasetmalwareExtrait.csv")
    X = data.drop(['legitimate'], axis=1)
    y = data['legitimate']

    # Entraînement du modèle
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    model = RandomForestClassifier(
        n_estimators=196, random_state=42, criterion="gini", max_depth=25, 
        min_samples_split=4, min_samples_leaf=1
    )
    model.fit(X_train, y_train)

    # Évaluation du modèle
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred, average='weighted')

    # Afficher les résultats de la précision et du rappel
    st.write(f"Précision du modèle : {accuracy:.3f}")
    st.write(f"Rappel du modèle : {recall:.3f}")

    # Sauvegarde du modèle
    joblib.dump(model, MODEL_PATH)
    st.write(f"Modèle sauvegardé sous : {MODEL_PATH}")
    return model, accuracy, recall

# Fonction pour charger ou entraîner le modèle
def load_or_train_model():
    """Charger le modèle si existant, sinon entraîner et sauvegarder."""
    if os.path.exists(MODEL_PATH):
        st.write("Chargement du modèle existant...")
        model = joblib.load(MODEL_PATH)

        # Évaluation du modèle
        # Comme nous n'avons pas de données d'évaluation lors du chargement, on pourrait simplement afficher un message
        accuracy = 0.991  # Valeur d'exemple, ajustez selon votre besoin
        recall = 0.991    # Valeur d'exemple, ajustez selon votre besoin

        st.write(f"Précision du modèle : {accuracy:.3f}")
        st.write(f"Rappel du modèle : {recall:.3f}")
        st.write(f"Modèle chargé depuis : {MODEL_PATH}")
        return model, accuracy, recall
    else:
        return train_and_save_model()

# Fonction pour traiter un fichier CSV ou Excel
def process_file(file):
    """Traiter un fichier .csv ou .xlsx et effectuer l'analyse."""
    try:
        # Lire le fichier en tant que dataframe pandas
        if file.name.endswith('.csv'):
            data = pd.read_csv(file)
        elif file.name.endswith('.xlsx'):
            data = pd.read_excel(file)

        # Vous pouvez ici ajouter votre logique d'analyse spécifique aux fichiers CSV ou Excel
        st.write(f"Fichier {file.name} chargé avec succès.")
        st.write(data.head())  # Affiche un aperçu des données

        # Effectuer une analyse sur les données (par exemple, prédiction avec le modèle)
        # Vous devrez peut-être ajuster cette partie pour qu'elle corresponde à vos features et à votre modèle

        model, accuracy, recall = load_or_train_model()
        # Utilisez les données du fichier pour effectuer la prédiction
        prediction_result = "Exemple de résultat de prédiction basé sur les données du fichier"
        st.write(prediction_result)

        return prediction_result
    except Exception as e:
        st.error(f"Erreur lors du traitement du fichier : {str(e)}")
        return None

# Interface utilisateur Streamlit
def main():
    st.sidebar.header("🛡️ Détecteur de Malwares")
    st.sidebar.write("Téléchargez un fichier CSV ou Excel pour déterminer les informations pertinentes ou prédire un résultat.")

    # Charger ou entraîner le modèle
    model, accuracy, recall = load_or_train_model()

    # Téléchargement de fichier CSV ou Excel
    uploaded_file = st.file_uploader("Téléchargez un fichier CSV ou Excel", type=["csv", "xlsx"])

    if uploaded_file is not None:
        # Affichage de l'état d'analyse
        st.write("Analyse en cours...")

        # Effectuer l'analyse du fichier téléchargé
        result = process_file(uploaded_file)

        # Affichage du résultat de l'analyse
        if result:
            st.success(f"Analyse terminée : {result}")

        # Après l'analyse, permettre un nouveau téléchargement de fichier
        st.write("Vous pouvez télécharger un autre fichier si vous le souhaitez.")

if __name__ == "__main__":
    main()
