#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "headers/KNN.h"

namespace py = pybind11;

PYBIND11_MODULE(algos, m) {
    m.doc() = "GPU KNN classifier (C++/CUDA, exposed via pybind11)";

    py::class_<KNN>(m, "KNN")
        .def(py::init<int>(), py::arg("k"))
        .def("train",
            [](KNN& self,
                const std::vector<float>& x,
                const std::vector<float>& y,
                int n_features) {
                    self.Train(x, y, n_features);
            },
            py::arg("x"),
            py::arg("y"),
            py::arg("n_features"))
        .def("predict",
            [](const KNN& self,
                const std::vector<float>& x,
                int n_samples) {
                    return self.Predict(x, n_samples);
            },
            py::arg("x"),
            py::arg("n_samples"))
        .def("sanity_check", &KNN::SanityCheck)
        ;
}
