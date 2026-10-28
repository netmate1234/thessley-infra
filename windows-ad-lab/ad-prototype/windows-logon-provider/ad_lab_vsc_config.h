#pragma once

// Disposable-VM proof only. These values describe the existing certificate
// and TPM VSC on MARTIN-WM; they are intentionally not portable defaults.
#define THESSLEY_AD_LAB_USER_SID L"S-1-5-21-1719900462-4250469598-2954734011-1101"
#define THESSLEY_AD_LAB_VSC_CONTAINER L"te-ThessleyVscLogon-0ef1969d-38db-09390"
#define THESSLEY_AD_LAB_VSC_PROVIDER L"Microsoft Base Smart Card Crypto Provider"
#define THESSLEY_AD_LAB_VSC_READER L"Microsoft Virtual Smart Card 0"
#define THESSLEY_AD_LAB_VSC_CARD L"Identity Device (Microsoft Generic Profile)"
// certutil -key -csp SC identifies this VSC key container as AT_KEYEXCHANGE.
#define THESSLEY_AD_LAB_VSC_KEYSPEC 1
