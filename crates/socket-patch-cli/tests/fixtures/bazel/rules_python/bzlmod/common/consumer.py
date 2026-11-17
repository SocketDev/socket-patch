# spdep is the dependency of spvictim: it stays on the index when spvictim
# is patched.
import spdep  # noqa: F401
import spvictim

print("OUT: " + spvictim.value())
