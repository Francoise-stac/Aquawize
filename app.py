from sqlalchemy import text
from datetime import timedelta
from views.models import User
from flask import Flask, render_template, send_file
import os
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
from views.extensions import jwt, swagger, metrics
from flask import request, redirect, url_for, flash, render_template
from werkzeug.security import check_password_hash
from flask_jwt_extended import (
    jwt_required,
    get_jwt,
    JWTManager,
    get_jwt_identity,
    create_access_token,
)
from views.models import User
from flask import (
    Flask,
    render_template,
    send_file,
    jsonify,
    request,
    redirect,
    url_for,
    flash,
    session,
)
import requests  # Import pour faire une requête à l'API de login
import logging
from flask import session, jsonify, redirect, url_for, render_template, flash
from views.models import User  # Assure-toi d'importer ton modèle d'utilisateur


app = Flask(__name__)


logging.basicConfig(level=logging.DEBUG)

jwt = JWTManager(app)
# Exemple de User pour illustrer
from views.extensions import db


# Définir le callback pour charger l'utilisateur à partir du token
@jwt.user_lookup_loader
def load_user(jwt_header, jwt_data):
    # Récupérer l'identité de l'utilisateur à partir du token
    identity = jwt_data["sub"]
    # Rechercher l'utilisateur dans la base de données en fonction de l'ID ou de l'email
    return User.query.filter_by(email=identity["email"]).first()


# @staticmethod
# def query_by_email(email):
#     return User.query.filter_by(email=email).first()


# @staticmethod
# def query_by_email(email):
#     # Simuler la récupération d'un utilisateur avec un mot de passe haché
#     if email == "f.djeumen@lacroix.group":
#         # Ce mot de passe est haché avec bcrypt
#         return User(
#             email="f.djeumen@lacroix.group",
#             password="$2b$13$qPNuHtpzXCYCVwMESUlGQO.N.0WsqlwGJsDLsJbzEFOk9yVdDiUxy",
#         )
#     return None


# Fonction pour créer l'application Flask
def create_app(test_config=None):
    app = Flask(__name__)

    # Configuration de base de l'application
    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["MAIL_SERVER"] = "smtp.office365.com"
    app.config["MAIL_PORT"] = 587
    app.config["MAIL_USERNAME"] = "no-reply-aquawize@lacroix.group"
    app.config["MAIL_PASSWORD"] = os.getenv("RECOVERY_EMAIL_PASS")
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USE_SSL"] = False
    app.config["MAIL_DEBUG"] = False
    app.config["BCRYPT_LOG_ROUNDS"] = 13  # Sécurité renforcée

    # Configuration pour la base de données
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_POOL_SIZE"] = 40
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
    }

    if test_config:
        # Si c'est en mode test, appliquer la configuration de test
        app.config.update(test_config)
        print("Database used for test :", app.config["SQLALCHEMY_DATABASE_URI"])
    else:
        # Configurer la base de données pour l'exécution normale
        app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
            "SQLALCHEMY_DATABASE_URI", "sqlite:///default.db"
        )
    print("Database used :", app.config["SQLALCHEMY_DATABASE_URI"])

    # Charger les extensions
    from views.extensions import db, bcrypt, migrate, mail, babel

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    swagger.init_app(app)
    metrics.init_app(app)
    migrate.init_app(app, db)

    def get_locale():
        return "fr"

    babel.init_app(app, locale_selector=get_locale)

    # Créer les tables et démarrer le mail lors de l'initialisation de l'application
    with app.app_context():
        try:
            mail.connect()
            db.create_all()
        except Exception as Err:
            print(Err)

    # Configurer JWT
    # app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
    app.config["SECRET_KEY"] = os.getenv(
        "SECRET_KEY", "super-secret-session-key"
    )  # Utiliser une clé par défaut si non définie
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret-jwt-key")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=300)
    app.config["JWT_COOKIE_CSRF_PROTECT"] = True
    app.config["JWT_COOKIE_SECURE"] = True  # Doit être True en production

    print(f"SECRET_KEY: {app.config['SECRET_KEY']}")
    print(f"JWT_SECRET_KEY: {app.config['JWT_SECRET_KEY']}")
    print(f"SQLALCHEMY_DATABASE_URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

    # Gestion des erreurs JWT
    from flask_jwt_extended.exceptions import (
        NoAuthorizationError,
        CSRFError,
        FreshTokenRequired,
        RevokedTokenError,
        UserLookupError,
        WrongTokenError,
    )
    from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError
    from views.error_handlers import (
        handle_DecodeError,
        handle_NoAuthorizationError,
        handle_CSRFError,
        handle_InvalidTokenError,
        handle_ExpiredSignatureError,
        handle_FreshTokenRequired,
        handle_RevokedTokenError,
        handle_BadRequest,
        handle_Unauthorized,
        handle_Forbidden,
        handle_NotFound,
        handle_MethodNotAllowed,
        handle_InternalServerError,
        handle_PendingRollbackError,
        handle_UserLookupError,
        handle_WrongTokenError,
        handle_IntegrityError,
        handle_NodeIDAbsentError,
    )
    from werkzeug.exceptions import (
        BadRequest,
        Unauthorized,
        Forbidden,
        NotFound,
        MethodNotAllowed,
        InternalServerError,
    )
    from sqlalchemy.exc import PendingRollbackError, IntegrityError
    from treelib.exceptions import NodeIDAbsentError

    # Gestion des erreurs SQLAlchemy et JWT
    app.register_error_handler(PendingRollbackError, handle_PendingRollbackError)
    app.register_error_handler(IntegrityError, handle_IntegrityError)
    app.register_error_handler(DecodeError, handle_DecodeError)
    app.register_error_handler(CSRFError, handle_CSRFError)
    app.register_error_handler(InvalidTokenError, handle_InvalidTokenError)
    app.register_error_handler(ExpiredSignatureError, handle_ExpiredSignatureError)
    app.register_error_handler(FreshTokenRequired, handle_FreshTokenRequired)
    app.register_error_handler(RevokedTokenError, handle_RevokedTokenError)
    app.register_error_handler(NoAuthorizationError, handle_NoAuthorizationError)
    app.register_error_handler(UserLookupError, handle_UserLookupError)
    app.register_error_handler(WrongTokenError, handle_WrongTokenError)

    app.register_error_handler(BadRequest, handle_BadRequest)
    app.register_error_handler(Unauthorized, handle_Unauthorized)
    app.register_error_handler(Forbidden, handle_Forbidden)
    app.register_error_handler(NotFound, handle_NotFound)
    app.register_error_handler(MethodNotAllowed, handle_MethodNotAllowed)
    app.register_error_handler(InternalServerError, handle_InternalServerError)
    app.register_error_handler(NodeIDAbsentError, handle_NodeIDAbsentError)

    # Initialiser les API
    from api import initialize_api

    initialize_api(app)

    # Charger les routes et les blueprints
    from views.auth import auth

    app.register_blueprint(auth)

    # Fonction de maintenance de la base de données avec un thread
    import threading
    import time

    def heartbeat():
        with app.app_context():
            while True:
                try:
                    db.session.execute(text("SELECT 1"))
                    db.session.commit()
                    # Supprimer les connexions inactives plus anciennes que 300 secondes
                    kill_query = text(
                        """
                        SELECT concat('KILL ', id, ';')
                        FROM information_schema.processlist
                        WHERE command = 'Sleep' AND time > 300;
                        """
                    )
                    results = db.session.execute(kill_query)
                    for row in results:
                        db.session.execute(text(row[0]))
                    db.session.commit()
                except Exception as e:
                    print("thread :", e)
                    db.session.remove()
                    db.engine.dispose()
                time.sleep(60)  # Repos de 60 secondes

    # Lancer le thread de maintenance si ce n'est pas en mode test
    if not test_config:
        threading.Thread(target=heartbeat, daemon=True).start()

    # Route pour l'accueil

    from werkzeug.security import generate_password_hash

    # Fonction pour créer un nouvel utilisateur et hacher le mot de passe
    def create_user(email, password):
        # Hacher le mot de passe avec bcrypt
        hashed_password = generate_password_hash(password, method="bcrypt")
        # Sauvegarder l'utilisateur avec le mot de passe haché dans la base de données
        user = User(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        logging.debug(
            f"Utilisateur créé avec l'email: {email} et mot de passe haché: {hashed_password}"
        )

    from werkzeug.security import check_password_hash

    # Fonction pour vérifier le mot de passe lors de la connexion
    def verify_user(email, password):
        user = User.query.filter_by(email=email).first()

        if not user:
            logging.error(f"Utilisateur non trouvé pour l'email: {email}")
            return False

        # Vérifier si le mot de passe correspond
        if check_password_hash(user.password, password):
            logging.debug(f"Le mot de passe pour {email} est correct.")
            return True
        else:
            logging.error(f"Mot de passe incorrect pour {email}")
            return False

    # Route for homepage
    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/check-session")
    def check_session():
        if app.secret_key:
            return f"Secret key is set: {app.secret_key}"
        else:
            return "Secret key is not set"

    @app.route("/login", methods=["GET", "POST"])
    def show_login():
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")

            logging.debug(f"Tentative de connexion avec l'email: {email}")

            if not email or not password:
                logging.error("Email ou mot de passe manquant.")
                flash("Email et mot de passe sont requis", "danger")
                return render_template("login.html")

            # Appel API pour valider l'utilisateur
            response = requests.post(
                "http://127.0.0.1:5000/api/V1/login",  # Utilisez l'URL complète de l'API de login
                json={"email": email, "password": password},
            )

            if response.status_code == 200:
                data = response.json()
                # Stocker le token JWT dans la session Flask
                session["access_token"] = data["access_token"]
                session["email"] = data[
                    "email"
                ]  # Storing email for use in the dashboard
                return redirect(url_for("dashboard"))
            else:
                flash("Identifiants invalides. Veuillez réessayer.", "danger")
                return render_template("login.html")

        return render_template("login.html")

    @app.route("/dashboard", methods=["GET", "POST"])
    def dashboard():
        results = None  # Initialisation de results
        performance_data = []  # Initialisation de performance_data

        try:
            # Requête pour récupérer les résultats d’entraînement
            training_response = requests.get(
                "http://127.0.0.1:5000/api/V1/get_training_results"
            )

            if training_response.status_code == 200:
                training_data = training_response.json()
                results = training_data.get("result", None)
                print("Résultats d'entraînement récupérés :", results)
            else:
                print(
                    "Erreur lors de la récupération des résultats d'entraînement, statut :",
                    training_response.status_code,
                )

            # Requête pour récupérer les données de gestion de la performance
            performance_response = requests.get(
                "http://127.0.0.1:5000/api/V1/PerformanceManagement",
                headers={
                    "Authorization": f"Bearer {request.cookies.get('access_token')}"
                },
            )

            if performance_response.status_code == 200:
                print(performance_response.json())
                performance_data = performance_response.json().get("result", [])
                print("Données de performance récupérées :", performance_data)
            else:
                print(
                    "Erreur lors de la récupération des données de performance, statut :",
                    performance_response.status_code,
                )

        except requests.exceptions.RequestException as e:
            print("Erreur lors de la requête :", str(e))
            flash("Impossible de récupérer les données requises.", "danger")
            return redirect(url_for("show_login"))

        # Rendre le template avec les données de résultats d’entraînement et de gestion de la performance
        return render_template(
            "dashboard.html", results=results, performance_data=performance_data
        )

    from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt

    @app.route("/api/V1/PerformanceManagement", methods=["GET"])
    @jwt_required()  # Exige que la requête inclue un token JWT valide
    def get_performance_management_data():
        # Extraire l'identité de l'utilisateur authentifié
        current_user = get_jwt_identity()
        logging.debug(f"Utilisateur authentifié : {current_user}")

        # Récupérer les paramètres de requête envoyés par le client
        counter_id = request.args.get("counter_id")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        # Validation des paramètres
        if not counter_id or not start_date or not end_date:
            return (
                jsonify(
                    {
                        "message": "Les paramètres counter_id, start_date et end_date sont requis"
                    }
                ),
                400,
            )

        # Paramètres pour la requête à l'API de gestion des performances
        params = {
            "start_date": start_date,
            "end_date": end_date,
            "counter_id": counter_id,
        }

        try:
            # Faire la requête GET vers l'API avec le token JWT dans l'en-tête Authorization
            response = requests.get(
                "http://127.0.0.1:5000/api/V1/PerformanceManagement",
                headers={"Authorization": request.headers.get("Authorization")},
                # params=params,
            )

            # Vérifier la réponse de l'API
            if response.status_code == 200:
                data = response.json()
                logging.debug(
                    "Données de gestion de la performance récupérées avec succès."
                )
                return jsonify(
                    {"message": "GET Success", "performance_data": data["result"]}
                )
            else:
                logging.error(
                    f"Erreur lors de la récupération des données : {response.status_code}"
                )
                return (
                    jsonify(
                        {
                            "message": "Erreur lors de la récupération des données de performance"
                        }
                    ),
                    response.status_code,
                )

        except Exception as e:
            logging.error(f"Une erreur est survenue : {str(e)}")
            return (
                jsonify({"message": "Une erreur est survenue lors de la requête"}),
                500,
            )

    from flask_jwt_extended import jwt_required, get_jwt_identity

    @app.route("/train_model/<counter_id>", methods=["POST"])
    @jwt_required()  # S'assurer que l'utilisateur est authentifié
    def train_model(counter_id):

        counter_id = request.json.get("counter_id")
        user = get_jwt_identity()
        token = get_jwt()
        if user is None:
            return jsonify({"message": "Utilisateur non trouvé"}), 404

        try:
            # current_user = get_jwt_identity()
            # Appeler l'API d'entraînement de modèle en passant le counter_id et le token JWT
            # Récupérer le token JWT
            # token = get_jwt()
            # Afficher le token JWT dans les logs pour vérification
            # logging.debug(f"Utilisateur actuel : {current_user}, Token JWT: {token}")

            response = requests.post(
                "http://127.0.0.1:5000/api/V1/ModelTraining",
                json={
                    "counter_id": counter_id,
                    "user": user,
                },  # Envoyer le counter_id comme payload JSON
                headers={"Authorization": f"Bearer {token}"},  # Ajouter le token JWT
            )

            # Vérifier si l'entraînement a réussi
            if response.status_code == 200:
                data = response.json()  # Récupérer la réponse de l'API
                # Afficher les résultats d'entraînement dans une vue
                return render_template(
                    "train_results.html", results=data["result"], token=token
                )
            else:
                # Afficher un message d'erreur si l'entraînement échoue
                error_message = f"L'entraînement du modèle a échoué avec le statut {response.status_code}. Réponse: {response.text}"

                flash(error_message, "danger")
                return redirect(url_for("dashboard"))
        except requests.RequestException as e:
            # Gérer les erreurs de connexion à l'API d'entraînement
            logging.exception("Erreur de connexion avec l'API d'entraînement.")
            flash(
                f"Une erreur de connexion est survenue lors de l'entraînement : {str(e)}",
                "danger",
            )
            return redirect(url_for("dashboard"))

        except Exception as e:
            # Gérer les erreurs de connexion ou autres erreurs inattendues
            flash(
                f"Une erreur est survenue lors de l'entraînement : {str(e)}", "danger"
            )
            return redirect(url_for("dashboard"))

    from flask_jwt_extended import jwt_required, get_jwt_identity

    @app.route("/inference_model/<counter_id>", methods=["POST"])
    @jwt_required()
    def inference_model(counter_id):
        try:
            # Récupérer l'identité de l'utilisateur et le token brut depuis l'en-tête
            # user = get_jwt_identity()
            token = request.headers.get("Authorization")  # Récupère le token JWT brut

            # Envoi de la requête POST avec counter_id dans l'URL
            response = requests.post(
                f"http://127.0.0.1:5000/api/V1/ModelInference?counter_id={counter_id}",
                headers={"Authorization": token},  # Envoi direct de l'en-tête brut
            )

            # Vérification de la réponse de l'API
            if response.status_code == 200:
                data = response.json()
                logging.debug(f"Réponse de l'API d'inférence : {data}")
                return jsonify(
                    {"message": "Inference Success", "result": data["result"]}
                )
            else:
                logging.error(
                    f"Échec de l'inférence. Statut : {response.status_code}. Réponse : {response.json()}"
                )
                return (
                    jsonify({"message": "Inference failed", "result": response.json()}),
                    response.status_code,
                )
        except Exception as e:
            logging.error(f"Erreur lors de l'inférence : {str(e)}")
            return jsonify({"message": f"Erreur lors de l'inférence: {str(e)}"}), 500

    # Route for logout
    @app.route("/logout")
    def logout():
        session.pop("access_token", None)  # Remove JWT from session
        return redirect(url_for("show_login"))

    ##############################
    ## Gestion des logs d'accès ##
    ##############################

    # API pour récupérer les logs d'accès
    from flask_jwt_extended import jwt_required, get_jwt_identity

    @app.route("/api/access-logs", methods=["GET"])
    @jwt_required()  # Nécessite un token JWT valide
    def get_access_logs():
        current_user = get_jwt_identity()  # Récupérer l'utilisateur actuel via le token
        access_logs = [
            {"date": "2024-10-12", "action": "Login", "ip_address": "192.168.1.1"},
            {
                "date": "2024-10-13",
                "action": "Viewed Dashboard",
                "ip_address": "192.168.1.2",
            },
            {"date": "2024-10-14", "action": "Logged out", "ip_address": "192.168.1.1"},
        ]
        return jsonify(access_logs=access_logs), 200

    ##########################
    ##    Visualisation des anomalies ##
    ##########################

    # Définir l'entity_path (chemin de base) comme dans l'API

    advance_performance_management_path = os.path.normpath(
        "./api/V1/managed_folders/m8xsQWd2"
    )
    entity_name = "aquawize"
    model_path = os.path.join(advance_performance_management_path, "Models")
    # Construction du chemin de base avec os.path.join
    entity_path = os.path.join(
        advance_performance_management_path, "Entities", entity_name
    )
    entity_path = os.path.normpath(entity_path)

    # @app.route("/")
    # def home():
    #     return render_template("base.html")

    @app.route("/anomalies")
    def show_anomalies():
        counter_id = "101177"  # Exemple d'ID de compteur
        anomalies_df = load_anomalies(counter_id)

        # Convertir les anomalies en dictionnaire pour les afficher dans la vue
        anomalies_list = anomalies_df.to_dict(orient="records")
        return render_template("anomalies.html", anomalies=anomalies_list)

    def load_anomalies(counter_id):
        # Construire le chemin vers le fichier des métriques
        metrics_path = os.path.join(
            entity_path, f"counter_{counter_id}", "metrics.json"
        )
        metrics_path = os.path.normpath(metrics_path)
        counter_path = os.path.join(entity_path, f"counter_{counter_id}")

        # Vérifier si le fichier des métriques existe
        if not os.path.exists(metrics_path):
            print(f"Metrics file not found at {metrics_path}")
            return pd.DataFrame(
                columns=["start", "end"]
            )  # Si métriques manquantes, renvoyer DataFrame vide

        # Chemin vers le fichier CSV des anomalies
        csv_file_path = os.path.join(counter_path, "anomalies_periods.csv")

        # Vérifier si le fichier CSV des anomalies existe et le charger
        if os.path.exists(csv_file_path):
            anomalies_df = pd.read_csv(csv_file_path)
            return anomalies_df
        else:
            print(f"Fichier CSV des anomalies non trouvé : {csv_file_path}")  # Debug
            return pd.DataFrame(columns=["start", "end"])

    ## Nouvelle route pour le graphique ###

    @app.route("/anomalies_plot/<counter_id>.png")
    def plot_anomalies(counter_id):
        anomalies_df = load_anomalies(counter_id)

        if anomalies_df.empty:
            return "No data to plot", 404

        # Convertir les colonnes "start" et "end" en datetime
        anomalies_df["start"] = pd.to_datetime(anomalies_df["start"])
        anomalies_df["end"] = pd.to_datetime(anomalies_df["end"])

        # Créer un graphique
        fig, ax = plt.subplots(figsize=(10, 6))

        # Pour chaque ligne dans le DataFrame, tracer une barre horizontale représentant la période d'anomalie
        for i, row in anomalies_df.iterrows():
            ax.plot([row["start"], row["end"]], [i, i], color="red", lw=4)

        # Configurer les axes
        ax.set_xlabel("Time")
        ax.set_ylabel("Anomalies")
        ax.set_title(f"Periods of Anomalies for Counter {counter_id}")
        ax.grid(True)

        # Formater l'axe x pour afficher les dates de manière lisible
        plt.gcf().autofmt_xdate()

        # Sauvegarder l'image dans un buffer pour l'envoyer directement
        img = BytesIO()
        plt.savefig(img, format="png")
        img.seek(0)

        return send_file(img, mimetype="image/png")

    return app


app = create_app()
if __name__ == "__main__":
    debug_mode = False if os.getenv("DEBUG_MODE") else True
    app.run(debug=debug_mode, host="0.0.0.0")
