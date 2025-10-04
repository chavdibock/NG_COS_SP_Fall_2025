#include <pybind11/pybind11.h>
#include "headers/OcSvm.h"

namespace py = pybind11;

// (optional utility from your snippet)
int add(int a, int b) { return a + b; }

PYBIND11_MODULE(algos, m) {
    m.doc() = "Algorithms bindings";

    // Expose OcSvm(int, double, int)
    py::class_<OcSvm>(m, "OcSvm")
        .def(py::init<int, double, int>(),
            py::arg("a"), py::arg("b"), py::arg("c"),
            "Construct OcSvm(a, b, c)");

    // keep your trivial function if you want it
    m.def("add", &add, py::arg("a"), py::arg("b"), "Return a + b.");
}
