#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "headers/KNN.h"
#include "headers/OcSvm.h"
#include "headers/gpu_oc_svm_kernel.h" 
#include "headers/benchmarks.h"
namespace py = pybind11;
using namespace std;
PYBIND11_MODULE(algos, m) {
    m.doc() = "GPU Machine Learning Library (KNN & OC-SVM)";

    // to be used as algos.KernelType.<kernel_type>
    py::enum_<KernelType>(m, "KernelType")
        .value("LINEAR", KernelType::LINEAR)
        .value("RBF", KernelType::RBF)
        .value("POLY", KernelType::POLY)
        .value("SIGMOID", KernelType::SIGMOID)
        .export_values();

    // KNN export
    py::class_<KNN>(m, "KNN")
        .def(py::init<int>(), py::arg("k"))
        .def("train",
            [](KNN& self, const vector<float>& x, const vector<float>& y, int n_features) {
                self.Train(x, y, n_features);
            },
            py::arg("x"), py::arg("y"), py::arg("n_features"))
        .def("predict",
            [](const KNN& self, const vector<float>& x, int n_samples) {
                return self.Predict(x, n_samples);
            },
            py::arg("x"), py::arg("n_samples"))
        .def("sanity_check", &KNN::SanityCheck);

    // OC-SVM  export
    py::class_<OcSvm>(m, "OcSvm")
        .def(py::init<int, float, float, float, int>(),
            py::arg("kernel") = (int)KernelType::RBF,
            py::arg("gamma") = 0.1f,
            py::arg("nu") = 0.1f,
            py::arg("coef0") = 0.0f,
            py::arg("degree") = 3)
        .def("train",
            [](OcSvm& self, const vector<float>& x, const vector<float>& y, int n_features) {
                self.Train(x, y, n_features);
            },
            py::arg("x"), py::arg("y"), py::arg("n_features"))
        .def("predict",
            [](const OcSvm& self, const vector<float>& x, int n_samples) {
                return self.Predict(x, n_samples);
            },
            py::arg("x"), py::arg("n_samples"))
        .def("get_params", &OcSvm::GetParams, "Get dictionary of model parameters");


    // Benchmark funktion to be used for evaluations
    m.def("roc_auc",
        &roc_auc,
        py::arg("scores"),
        py::arg("labels"),
        "Compute ROC-AUC");

    m.def("recall",
        &recall_at_threshold,
        py::arg("scores"),
        py::arg("labels"),
        py::arg("threshold") = 0.5f,
        "Compute recall");
}