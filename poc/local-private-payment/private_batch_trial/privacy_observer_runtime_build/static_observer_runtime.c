#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <Python.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "generated_observer_frozen.h"

extern int kpb_static_sha256(
    const unsigned char *, size_t, unsigned char[32]);

enum {
    KPB_CAPSULE_FD = 40,
    KPB_SOURCE_FD = 60,
    KPB_ASSET_FD = 61,
    KPB_OUTPUT_FD = 62,
    KPB_MIN_CAPSULE_BYTES = 7866,
};

static int exact_capsule(void) {
    struct stat status;
    const int required_seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    return fstat(KPB_CAPSULE_FD, &status) == 0 &&
        S_ISREG(status.st_mode) && status.st_size >= KPB_MIN_CAPSULE_BYTES &&
        (uint64_t)status.st_size <= (4ULL << 30) + (1ULL << 20) &&
        (fcntl(KPB_CAPSULE_FD, F_GETFL) & O_ACCMODE) == O_RDONLY &&
        (fcntl(KPB_CAPSULE_FD, F_GETFD) & FD_CLOEXEC) == 0 &&
        (fcntl(KPB_CAPSULE_FD, F_GET_SEALS) & required_seals) ==
            required_seals;
}

static int exact_empty_output(void) {
    struct stat status;
    return fstat(KPB_OUTPUT_FD, &status) == 0 &&
        S_ISREG(status.st_mode) && status.st_size == 0 &&
        (fcntl(KPB_OUTPUT_FD, F_GETFL) & O_ACCMODE) == O_WRONLY &&
        (fcntl(KPB_OUTPUT_FD, F_GETFD) & FD_CLOEXEC) == 0 &&
        fcntl(KPB_OUTPUT_FD, F_GET_SEALS) == 0;
}

static PyObject *kpb_sha256_digest(PyObject *self, PyObject *args) {
    (void)self;
    Py_buffer input;
    if (!PyArg_ParseTuple(args, "y*", &input)) return NULL;
    unsigned char digest[32];
    const int ok = kpb_static_sha256(
        (const unsigned char *)input.buf, (size_t)input.len, digest);
    PyBuffer_Release(&input);
    if (!ok) {
        memset(digest, 0, sizeof(digest));
        PyErr_SetString(PyExc_RuntimeError, "kpb-sha256-evp-refused");
        return NULL;
    }
    PyObject *result = PyBytes_FromStringAndSize(
        (const char *)digest, (Py_ssize_t)sizeof(digest));
    memset(digest, 0, sizeof(digest));
    return result;
}

static PyMethodDef kpb_sha256_methods[] = {
    {"digest", kpb_sha256_digest, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL},
};
static struct PyModuleDef kpb_sha256_module = {
    PyModuleDef_HEAD_INIT, "kpb_sha256", NULL, -1,
    kpb_sha256_methods, NULL, NULL, NULL, NULL,
};
PyMODINIT_FUNC PyInit_kpb_sha256(void) {
    return PyModule_Create(&kpb_sha256_module);
}

extern PyObject *PyMarshal_Init(void);
extern PyObject *PyInit__imp(void);
extern PyObject *PyInit_gc(void);
extern PyObject *PyInit__ast(void);
extern PyObject *PyInit__tokenize(void);
extern PyObject *PyInit__contextvars(void);
extern PyObject *_PyWarnings_Init(void);
extern PyObject *PyInit__string(void);
extern PyObject *PyInit_atexit(void);
extern PyObject *PyInit_faulthandler(void);
extern PyObject *PyInit_posix(void);
extern PyObject *PyInit__signal(void);
extern PyObject *PyInit__tracemalloc(void);
extern PyObject *PyInit__suggestions(void);
extern PyObject *PyInit__codecs(void);
extern PyObject *PyInit__collections(void);
extern PyObject *PyInit_errno(void);
extern PyObject *PyInit__io(void);
extern PyObject *PyInit_itertools(void);
extern PyObject *PyInit__sre(void);
extern PyObject *PyInit__sysconfig(void);
extern PyObject *PyInit__thread(void);
extern PyObject *PyInit_time(void);
extern PyObject *PyInit__types(void);
extern PyObject *PyInit__typing(void);
extern PyObject *PyInit__weakref(void);
extern PyObject *PyInit__abc(void);
extern PyObject *PyInit__functools(void);
extern PyObject *PyInit__locale(void);
extern PyObject *PyInit__operator(void);
extern PyObject *PyInit__stat(void);
extern PyObject *PyInit__symtable(void);
extern PyObject *PyInit__struct(void);
extern PyObject *PyInit__json(void);
extern PyObject *PyInit_fcntl(void);

struct _inittab _PyImport_Inittab[] = {
    {"atexit", PyInit_atexit},
    {"faulthandler", PyInit_faulthandler},
    {"posix", PyInit_posix},
    {"_signal", PyInit__signal},
    {"_tracemalloc", PyInit__tracemalloc},
    {"_suggestions", PyInit__suggestions},
    {"_codecs", PyInit__codecs},
    {"_collections", PyInit__collections},
    {"errno", PyInit_errno},
    {"_io", PyInit__io},
    {"itertools", PyInit_itertools},
    {"_sre", PyInit__sre},
    {"_sysconfig", PyInit__sysconfig},
    {"_thread", PyInit__thread},
    {"time", PyInit_time},
    {"_types", PyInit__types},
    {"_typing", PyInit__typing},
    {"_weakref", PyInit__weakref},
    {"_abc", PyInit__abc},
    {"_functools", PyInit__functools},
    {"_locale", PyInit__locale},
    {"_operator", PyInit__operator},
    {"_stat", PyInit__stat},
    {"_symtable", PyInit__symtable},
    {"_struct", PyInit__struct},
    {"_json", PyInit__json},
    {"fcntl", PyInit_fcntl},
    {"kpb_sha256", PyInit_kpb_sha256},
    {"marshal", PyMarshal_Init},
    {"_imp", PyInit__imp},
    {"gc", PyInit_gc},
    {"_ast", PyInit__ast},
    {"_tokenize", PyInit__tokenize},
    {"_contextvars", PyInit__contextvars},
    {"_warnings", _PyWarnings_Init},
    {"_string", PyInit__string},
    {"builtins", NULL},
    {"sys", NULL},
    {NULL, NULL},
};

static int exact_sealed_archive(
        int fd, uint64_t expected_size,
        const unsigned char expected_sha256[32]) {
    struct stat status;
    const int required_seals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
            (uint64_t)status.st_size != expected_size ||
            (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY ||
            (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0 ||
            (fcntl(fd, F_GET_SEALS) & required_seals) != required_seals)
        return 0;

    if (expected_size == 0 || expected_size > 64U * 1024U * 1024U)
        return 0;
    unsigned char *buffer = malloc((size_t)expected_size);
    if (buffer == NULL) return 0;
    uint64_t at = 0;
    while (at < expected_size) {
        ssize_t count;
        do {
            count = pread(fd, buffer + at,
                (size_t)(expected_size - at), (off_t)at);
        } while (count < 0 && errno == EINTR);
        if (count <= 0) {
            memset(buffer, 0, (size_t)expected_size);
            free(buffer);
            return 0;
        }
        at += (uint64_t)count;
    }
    unsigned char actual[32];
    const int ok = kpb_static_sha256(
        buffer, (size_t)expected_size, actual) &&
        memcmp(actual, expected_sha256, sizeof(actual)) == 0;
    memset(buffer, 0, (size_t)expected_size);
    free(buffer);
    memset(actual, 0, sizeof(actual));
    return ok;
}

static int initialize_frozen_python(void) {
    PyImport_FrozenModules = kpb_observer_frozen_modules;
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.site_import = 0;
    config.user_site_directory = 0;
    config.use_environment = 0;
    config.write_bytecode = 0;
    config.install_signal_handlers = 0;
    config.parse_argv = 0;
    config.safe_path = 1;
    config.use_hash_seed = 1;
    config.hash_seed = 0;
    config.module_search_paths_set = 1;
    PyStatus status = PyConfig_SetString(
        &config, &config.program_name, L"kpb-static-observer");
    if (!PyStatus_Exception(status))
        status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        Py_ExitStatusException(status);
        return 0;
    }
    const char *lock_imports =
        "import sys\n"
        "sys.path.clear()\n"
        "sys.path_hooks.clear()\n"
        "sys.path_importer_cache.clear()\n"
        "sys.meta_path[:] = [x for x in sys.meta_path "
        "if getattr(x, '__name__', '') in "
        "('BuiltinImporter', 'FrozenImporter')]\n";
    return PyRun_SimpleString(lock_imports) == 0;
}

int main(void) {
    if (!exact_capsule() || !exact_empty_output() ||
            !exact_sealed_archive(
            KPB_SOURCE_FD, kpb_source_archive_size,
            kpb_source_archive_sha256) ||
            !exact_sealed_archive(
                KPB_ASSET_FD, kpb_asset_archive_size,
                kpb_asset_archive_sha256))
        return 71;
    if (!initialize_frozen_python())
        return 72;
    PyObject *module = PyImport_ImportModule(kpb_entrypoint_module);
    PyObject *function = module == NULL ? NULL :
        PyObject_GetAttrString(module, kpb_entrypoint_function);
    PyObject *result = function == NULL ? NULL :
        PyObject_CallNoArgs(function);
    long code = result == NULL ? -1 : PyLong_AsLong(result);
    if (PyErr_Occurred()) {
        PyErr_Clear();
        code = -1;
    }
    Py_XDECREF(result);
    Py_XDECREF(function);
    Py_XDECREF(module);
    const int finalize = Py_FinalizeEx();
    if (finalize != 0) return 73;
    if (code == 0 || code == 78) return (int)code;
    return 73;
}
