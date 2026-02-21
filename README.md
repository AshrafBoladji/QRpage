# IA Security Toolkit — Guide d’utilisation rapide pour développeurs IA

> Renforcez vos modèles IA contre les abus: validation stricte des données, détection d’anomalies & de drift, auth JWT (users & IoT), détection comportementale, et protections anti-extraction (leurre, bruitage).

Ce dépôt fournit des modules prêts à l’emploi pour sécuriser des pipelines et API de modèles IA utilisés en maintenance prédictive. Vous pouvez copier/importer les fichiers dans votre projet et utiliser directement les fonctions exposées.

Contenu principal
- security/: Authentification et autorisation (JWT, capteurs IoT, permissions)
- data_protection/: Validation de schéma, détection d’anomalies, détection de drift
- model_protection/: Protection contre l’extraction/abus de modèle (leurre, bruit)
- monitor/: Journalisation structurée centralisée
- main.py: Exemple d’API FastAPI intégrant tous les modules

Astuce intégration rapide (copier-coller)
- Copier les dossiers security/, data_protection/, model_protection/, monitor/ dans votre projet
- Adapter les imports selon votre namespace (ex.: from mypkg.security.auth import ...)
- Remplacer les secrets par des variables d’environnement
- Brancher log_event partout pour une traçabilité homogène

Installation minimale
- Python 3.10+
- pip install -r requirements.txt

Structure des logs
Tous les modules journalisent via monitor/logger.log_event(severity, component, security_level, message, status). Un fichier api_logs.log est écrit à la racine.

====================================================================================================
1) Module de journalisation — monitor/logger.py
====================================================================================================
Objet: Fournit une fonction de log structurée unique pour tous les évènements de sécurité et métier.

Fonctions clés
- log_event(severity, component, security_level, message, status="INFO")
  - severity: INFO | WARNING | ERROR | ALERT
  - component: ex. AUTH_MODULE, PREDICT_ENDPOINT, DRIFT_DETECTOR
  - security_level: S1..S4 selon la sensibilité
  - status: ACCEPTED | BLOCKED | FLAGGED | ERROR | STABLE | INVESTIGATE
- log_simple(message, severity="INFO"): version simplifiée

Exemple d’usage
from monitor.logger import log_event
log_event("INFO", "MY_COMPONENT", "S2", "Action réussie", "ACCEPTED")

Intégration
- Importez monitor/logger.py et utilisez log_event partout pour une traçabilité uniforme.

====================================================================================================
2) Sécurité & Authentification — security/
====================================================================================================
Fichier: security/auth.py
Objet: Authentification JWT (utilisateurs et capteurs IoT), refresh, révocation, permissions.

Principales constantes
- SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS

Modèles Pydantic
- TokenResponse, TokenPayload, LoginRequest, User

Fonctions principales
- create_access_token(user_id: str, expires_delta: Optional[timedelta]=None) -> str
- create_refresh_token(user_id: str) -> str
- create_sensor_token(sensor_id: str, expires_hours: int=24) -> str
- authenticate_user(username: str, password: str) -> Optional[dict]
- verify_token(token: str, token_type: str="access") -> dict
- get_current_user(credentials=Depends(HTTPBearer())) -> dict   [pour FastAPI]
- revoke_token(token: str) -> None
- is_token_revoked(token: str) -> bool
- check_permission(user_id: str, required_permission: str) -> bool
- require_permission(required_permission: str) -> FastAPI dependency
- authenticate_sensor(sensor_id: str, client_secret: str) -> Optional[dict]
- get_current_sensor(credentials=Depends(HTTPBearer())) -> dict  [pour FastAPI]

Exemples d’usage hors FastAPI
from security.auth import create_access_token, verify_token, authenticate_user

user = authenticate_user("admin", "admin_password_123")
if user:
    token = create_access_token(user["user_id"])  # JWT signé
    payload = verify_token(token, token_type="access")

Capteurs IoT (M2M)
from security.auth import authenticate_sensor, create_sensor_token
sensor = authenticate_sensor("sensor_001", "sensor_secret_key_001_change_in_production")
if sensor:
    sensor_token = create_sensor_token("sensor_001", expires_hours=24)

Permissions dans une route FastAPI
from security.auth import require_permission
@app.get("/admin-only")
async def admin_only(current=Depends(require_permission("train"))):
    return {"ok": True}

Fichier: security/behavior_detection.py
Objet: Détection d’abus/comportements anormaux (rafales de requêtes, sauts anormaux de features) en mémoire.

Fonction clé
- detect_behavior(subject_id: str, features: Union[dict, iterable, float, int]) -> bool
  - Retourne True si activité suspecte (burst rate ou distance z-score élevée) et journalise un ALERT.

Usage minimal
from security.behavior_detection import detect_behavior
suspicious = detect_behavior("user_123", {"temp_mean": 70.3, "vib_mean": 2.1})
if suspicious:
    # activer contre-mesures (rate-limit, shadow model, etc.)

Remarques
- Stockage en mémoire (deque). Pour la prod multi-process, utiliser Redis ou équivalent.

====================================================================================================
3) Protection des données — data_protection/
====================================================================================================
Fichier: data_protection/schema_validator.py
Objet: Valide la structure et les contraintes des données capteurs via Pydantic.

Classes/Fonctions
- class MachineData(BaseModel): définit toutes les contraintes (ranges, cohérences)
- validate_data(data: dict) -> MachineData
- print_schema_info() -> imprime le JSON Schema

Usage
from data_protection.schema_validator import validate_data
validated = validate_data(payload_dict)  # lève si invalide; log INFO/ALERT

Fichier: data_protection/anomaly_detector.py
Objet: Détection d’anomalies point-in-time via IsolationForest entraîné au chargement sur le dataset fourni.

Fonction
- detect_anomaly(features: list[float]) -> bool
  - features attend un vecteur dans l’ordre des colonnes numériques utilisées à l’entrainement (le code d’exemple construit ce vecteur depuis MachineData dans main.py).
  - Retourne True si anomalie (log CRITICAL_ALERT/INFO)

Usage
from data_protection.anomaly_detector import detect_anomaly
is_anomaly = detect_anomaly([maintenance_age_days, vib_mean, vib_std, ...])

Fichier: data_protection/drift_detector.py
Objet: Détection de drift univarié sur 9 variables (KS test + z-score + score combiné) avec baselines extraites du dataset.

Constantes
- DRIFT_FEATURES: liste des 9 variables suivies

Fonctions
- detect_drift(new_values_dict: dict, verbose: bool=False) -> dict
  - Retour: {
      'drift_detected': bool,
      'global_drift_score': float,
      'features_drifted': list,
      'feature_scores': dict[str, float],
      'details': dict[str, {...}]
    }
- print_baselines_summary() -> affiche les stats baseline

Usage
from data_protection.drift_detector import detect_drift
window = {
  'temp_mean': [65, 66, 67], 'temp_max': [80, 82, 81], 'vib_mean': [3.5, 3.7, 3.6],
  'vib_rms': [4.0, 4.1, 3.9], 'oil_particle_count': [50, 52, 49], 'acoustic_energy': [100, 98, 101],
  'current_mean': [12, 13, 12.5], 'rpm_mean': [1500, 1502, 1498], 'vib_std': [0.5, 0.52, 0.51]
}
result = detect_drift(window)
if result['drift_detected']:
    # déclencher investigation/alertes

====================================================================================================
4) Protection du modèle — model_protection/
====================================================================================================
Fichier: model_protection/prediction_guard.py
Objet: Bruitage sélectif des sorties si activité suspecte pour limiter l’extraction de modèle.

Fonction
- guard_prediction(prediction: int|float, suspicious: bool=False) -> int|float
  - Si suspicious=True, 10% des réponses sont inversées; log WARNING/"PROTECTED".

Usage
from model_protection.prediction_guard import guard_prediction
final_pred = guard_prediction(raw_pred, suspicious)

Fichier: model_protection/shadow_model.py
Objet: Modèle leurre (décoy) pour détourner les requêtes malveillantes.

Fonction
- shadow_predict() -> int
  - Journalise CRITICAL et retourne 0 (prédiction bidon)

Usage
from model_protection.shadow_model import shadow_predict
if suspicious:
    return shadow_predict()

Ajoutez une couche “Decoy” dynamique (recommandé)
- Pour renforcer la sécurité contre l’extraction de modèle, implémentez un modèle fictif dans shadow_model qui sera activé dynamiquement lorsque detect_behavior signale une activité suspecte. L’objectif est de perturber les tentatives d’extraction, produire des résultats biaisés/instables et rendre tout clone attaquant incohérent.

Idée d’implémentation simplifiée (shadow_model.py)
from monitor.logger import log_event
import random

def shadow_predict(features=None):
    # Biais contrôlé + bruit: renvoyer une sortie plausible mais instable
    # Exemple binaire: inverser aléatoirement avec proba dépendant d’un motif
    log_event("CRITICAL", "SHADOW_MODEL", "S2", "Réponse fournie par le modèle-leurre", "DECOY_ACTIVE")
    if features is None:
        return 0
    r = random.random()
    return 1 if r > 0.6 else 0

Activation côté service
from security.behavior_detection import detect_behavior
from model_protection.shadow_model import shadow_predict

suspicious = detect_behavior(subject_id, feature_snapshot)
if suspicious:
    return {"failure_next_24h": shadow_predict(features)}

Bonnes pratiques decoy
- Garder des sorties crédibles (bornes/typage respectés)
- Introduire biais + variabilité contrôlée (éviter un pattern trivial)
- Journaliser chaque activation et surveiller
- Masquer les indices dans les erreurs/réponses

====================================================================================================
5) Exemple d’intégration API — main.py (FastAPI)
====================================================================================================
Démarrer l’API
- uvicorn main:app --reload

Flux supportés
- /auth/login: login utilisateur -> access_token (30 min) + refresh_token (7 j)
- /auth/refresh: génère un nouvel access_token à partir d’un refresh_token
- /auth/logout: révocation d’un access_token
- /auth/sensor-login: authentifie un capteur IoT -> token 24h (type "sensor")
- /predict: endpoint protégé (accepte token user OU sensor)
  - Valide données (schema_validator)
  - Détecte anomalies (anomaly_detector)
  - Détecte comportement suspect (behavior_detection)
  - Produit prédiction simple puis applique guard_prediction
- /protected/model-info: nécessite permission "train"
- /health: status

Extrait d’utilisation dans /predict
from data_protection.schema_validator import validate_data
from data_protection.anomaly_detector import detect_anomaly
from security.behavior_detection import detect_behavior
from model_protection.prediction_guard import guard_prediction

validated = validate_data(payload)
features = [validated.maintenance_age_days, validated.vib_mean, ..., validated.oil_particle_count]
if detect_anomaly(features):
    return {"status": "anomaly detected"}
suspicious = detect_behavior(subject_id, validated.temp_mean)
raw_pred = 1 if validated.temp_mean > 90 else 0
final_pred = guard_prediction(raw_pred, suspicious)

====================================================================================================
6) Bonnes pratiques d’intégration dans VOTRE projet
====================================================================================================
- Copier les dossiers security/, data_protection/, model_protection/, monitor/ dans votre codebase.
- Centraliser les logs via monitor/logger.log_event et configurer les handlers (fichier, SIEM, etc.).
- Remplacer SECRET_KEY par une clé robuste en variable d’environnement; stocker USERS_DB et SENSOR_CREDENTIALS ailleurs.
- Externaliser l’historique behavior_detection dans Redis pour un déploiement multi-instances.
- Adapter anomaly_detector pour entraîner sur VOS données (et persister le modèle) au lieu de charger le CSV fourni.
- Vérifier vos chemins d’import selon votre arborescence (ex.: from mypkg.security.auth import ...).
- Ajouter un shadow model crédible et contrôlable (cf. section Decoy) pour brouiller toute tentative d’extraction.

Checklist d’intégration rapide
- [ ] Installer requirements et variables d’environnement (SECRET_KEY)
- [ ] Brancher vos endpoints à get_current_user/get_current_sensor
- [ ] Valider les entrées via validate_data
- [ ] Ajouter detect_anomaly/detect_drift sur vos fenêtres temporelles
- [ ] Appliquer detect_behavior pour chaque sujet (user/sensor)
- [ ] Protéger les sorties via guard_prediction et/ou redirection shadow_model
- [ ] Surveiller api_logs.log et exporter vers observabilité

Licence
Ce code est fourni à des fins éducatives et de démonstration. Durcissez avant production.
