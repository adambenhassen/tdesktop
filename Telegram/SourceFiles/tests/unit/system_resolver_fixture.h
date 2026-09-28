#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void UnitSystemResolverSetAnswers(const uint32_t *answers, size_t count);
int UnitSystemResolverLookups(void);

#ifdef __cplusplus
}
#endif
