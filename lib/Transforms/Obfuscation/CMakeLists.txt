#add_llvm_library(LLVMObfuscation
#  CryptoUtils.cpp
#  StringObfuscation.cpp
#  Substitution.cpp
#  Flattening.cpp
#  Utils.cpp
#  )

#add_dependencies(LLVMObfuscation intrinsics_gen)

add_llvm_loadable_module( LLVMObfuscation
  CryptoUtils.cpp
  StringObfuscation.cpp
  Substitution.cpp
  Flattening.cpp
  Utils.cpp

  DEPENDS
  intrinsics_gen
  PLUGIN_TOOL
  opt
  )