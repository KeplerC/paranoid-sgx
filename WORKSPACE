workspace(name = "asylo_examples")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository", "new_git_repository")
# Download and use the Asylo SDK.

# http_archive(
#     name = "com_google_asylo",
#     sha256 = "bb6e9599f3e174321d96616ac8069fac76ce9d2de3bd0e4e31e1720c562e83f7",
#     strip_prefix = "asylo-0.6.0",
#     urls = ["https://github.com/google/asylo/archive/v0.6.0.tar.gz"],
# )

# Rule repository, note that it's recommended to use a pinned commit to a released version of the rules

# git_repository(
#   name = "rules_foreign_cc",

# )

http_archive(
    name = "rules_foreign_cc",
    sha256 = "d54742ffbdc6924f222d2179f0e10e911c5c659c4ae74158e9fe827aad862ac6",
    strip_prefix = "rules_foreign_cc-0.2.0",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/0.2.0.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")


rules_foreign_cc_dependencies()

_ALL_CONTENT = """\
filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"]
)
"""


# assimp source code repository
http_archive(
    name = "assimp",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "assimp-5.0.1",
    sha256 = "11310ec1f2ad2cd46b95ba88faca8f7aaa1efe9aa12605c55e3de2b977b3dbfc",
    urls = [
        "https://github.com/assimp/assimp/archive/refs/tags/v5.0.1.tar.gz",
    ],
)

#fcl 
http_archive(
    name = "fcl",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "fcl-0.6.1",
    sha256 = "c8a68de8d35a4a5cd563411e7577c0dc2c626aba1eef288cb1ca88561f8d8019",
    urls = [
        "https://github.com/flexible-collision-library/fcl/archive/refs/tags/v0.6.1.tar.gz",
    ],
)

#eigen3 
http_archive(
    name = "eigen",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "eigen-git-mirror-3.3.7",
    urls = [
        "https://github.com/eigenteam/eigen-git-mirror/archive/refs/tags/3.3.7.tar.gz",
    ],
    sha256 = "a8d87c8df67b0404e97bcef37faf3b140ba467bc060e2b883192165b319cea8d",
)

http_archive(
    name = "ccd",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "libccd-2.1",
    urls = [
        "https://github.com/danfis/libccd/archive/refs/tags/v2.1.tar.gz",
    ],
)


git_repository(
    name = "com_google_asylo",
    remote = "https://github.com/KeplerC/asylo.git",
    commit = "afb306d0f9d5e3e550c477bc1ba2c38db31dcd2d",
)

load(
    "@com_google_asylo//asylo/bazel:asylo_deps.bzl",
    "asylo_deps",
    "asylo_testonly_deps",
)

asylo_deps()

asylo_testonly_deps()

# sgx_deps is only needed if @linux_sgx is used.
load("@com_google_asylo//asylo/bazel:sgx_deps.bzl", "sgx_deps")

sgx_deps()

# remote_deps is only needed if remote backend is used.
load("@com_google_asylo//asylo/bazel:remote_deps.bzl", "remote_deps")

remote_deps()

# grpc_deps is only needed if gRPC is used. Projects using gRPC as an external
# dependency must call both grpc_deps() and grpc_extra_deps().
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()

load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")

grpc_extra_deps()



local_repository(
  name = "zmq",
  path = "third_party/zmq",
)

http_archive(
  name = "com_google_absl",
  urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20200923.3.zip"],
)