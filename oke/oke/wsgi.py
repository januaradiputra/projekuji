# file backend/server/server/wsgi.py
import os
from django.core.wsgi import get_wsgi_application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'oke.settings')
application = get_wsgi_application()

# ML registry
import inspect
from apps.ml.registry import MLRegistry
from apps.ml.phising_classifier.svm_phising import PhisingClassifier

try:
    registry = MLRegistry() # create ML registry
    # Random Forest classifier
    rf = PhisingClassifier()
    # add to ML registry
    registry.add_algorithm(endpoint_name="phising_classifier",
                            algorithm_object=rf,
                            algorithm_name="svm",
                            algorithm_status="production",
                            algorithm_version="0.0.1",
                            owner="gemastik",
                            algorithm_description="Phising Detection using SVM Classifier",
                            algorithm_code=inspect.getsource(PhisingClassifier))

except Exception as e:
    print("Exception while loading the algorithms to the registry,", str(e))