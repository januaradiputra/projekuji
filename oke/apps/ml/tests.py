from django.test import TestCase
import inspect
from apps.ml.registry import MLRegistry
from apps.ml.phising_classifier.svm_phising import PhisingClassifier

class MLTests(TestCase):
    def test_registry(self):
        registry = MLRegistry()
        self.assertEqual(len(registry.endpoints), 0)
        endpoint_name = "phising_classifier"
        algorithm_object = PhisingClassifier()
        algorithm_name = "phising svm"
        algorithm_status = "production"
        algorithm_version = "0.0.1"
        algorithm_owner = "gemastik"
        algorithm_description = "Phising Detection using SVM Classifier"
        algorithm_code = inspect.getsource(PhisingClassifier)
        # add to registry
        registry.add_algorithm(endpoint_name, algorithm_object, algorithm_name,
                    algorithm_status, algorithm_version, algorithm_owner,
                    algorithm_description, algorithm_code)
        # there should be one endpoint available
        self.assertEqual(len(registry.endpoints), 1)
        
    def test_rf_algorithm(self):
        input_data = "https://www.trademzpro.com/admin/"
        my_alg = PhisingClassifier()
        response = my_alg.prediksi(input_data)
        print(response)
        