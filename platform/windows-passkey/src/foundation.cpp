#include "librarian/windows_passkey/foundation.h"

static_assert(
    librarian::windows_passkey::current_readiness() ==
    librarian::windows_passkey::readiness::scaffold_only);
