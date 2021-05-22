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


# assimp source code repository
new_local_repository(
  name = "assimp",
  path = "assimp",
  build_file = "//src:BUILD.assimp",
)

new_local_repository(
  name = "fcl",
  path = "fcl",
  build_file = "//src:BUILD.fcl",
)

# snappy
http_archive(
    name = "com_github_google_snappy",
    url = "https://github.com/google/snappy/archive/ed3b7b2.tar.gz",
    strip_prefix = "snappy-ed3b7b242bd24de2ca6750c73f64bee5b7505944",
    sha256 = "88a644b224f54edcd57d01074c2d6fd6858888e915c21344b8622c133c35a337",
    build_file = "third-party/snappy.BUILD",
)

bind(
    name = "snappy",
    actual = "@com_github_google_snappy//:snappy",
)

bind(
    name = "snappy_config",
    actual = "//third-party/snappy_config:config"
)

http_archive(
  name = "com_github_google_glog",
  build_file = "third-party/glog.BUILD",
  strip_prefix = "glog-a6a166db069520dbbd653c97c2e5b12e08a8bb26",
  url = "https://github.com/google/glog/archive/a6a166db069520dbbd653c97c2e5b12e08a8bb26.tar.gz"
)

bind(
    name = "glog",
    actual = "@com_github_google_glog//:glog",
)


http_archive(
    name = "com_github_facebook_rocksdb",
    url = "https://github.com/facebook/rocksdb/archive/v6.8.1.tar.gz",
    strip_prefix = "rocksdb-6.8.1",
    build_file = "third-party/com_github_facebook_rocksdb/BUILD",
)

bind(
    name = "rocksdb",
    actual = "@com_github_facebook_rocksdb//:rocksdb",
)

# http_archive(
#     name = "assimp",
#     build_file = "//src:BUILD.assimp",
#     # sha256 = "60080d8ab4daaab309f65b3cffd99f19eb1af8d05623fff469b9b652818e286e",
#     strip_prefix = "assimp-4.0.1",
#     urls = ["https://github.com/assimp/assimp/archive/v4.0.1.tar.gz"],
# )

#fcl 
# http_archive(
#     name = "fcl",
#     strip_prefix = "fcl-0.6.1",
#     sha256 = "c8a68de8d35a4a5cd563411e7577c0dc2c626aba1eef288cb1ca88561f8d8019",
#     urls = [
#         "https://github.com/flexible-collision-library/fcl/archive/refs/tags/v0.6.1.tar.gz",
#     ],
#     build_file = "//src:BUILD.fcl",
# )

#eigen3 
http_archive(
    name = "eigen",
    strip_prefix = "eigen-git-mirror-3.3.7",
    urls = [
        "https://github.com/eigenteam/eigen-git-mirror/archive/refs/tags/3.3.7.tar.gz",
    ],
    sha256 = "a8d87c8df67b0404e97bcef37faf3b140ba467bc060e2b883192165b319cea8d",
    build_file = "//src:BUILD.eigen",
)

http_archive(
    name = "libccd",
    build_file = "//src:BUILD.libccd",
    strip_prefix = "libccd-2.1",
    urls = [
        "https://github.com/danfis/libccd/archive/refs/tags/v2.1.tar.gz",
    ],
)

new_git_repository(
    name = "nigh",
    remote = "https://github.com/UNC-Robotics/nigh.git",
    commit = "157eee0c5748fa6a192c84f46a6d202e10b1710d",
    build_file = "//src:BUILD.nigh",
)

git_repository(
    name = "com_google_asylo",
    remote = "https://github.com/KeplerC/asylo.git",
    commit = "89aa34697144f5b12a9b20da59b795fa702410a1",
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