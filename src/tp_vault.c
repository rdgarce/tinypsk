#include "tp_vault.h"
#include "tp_sha256.h"
#include "host.h"

typedef struct tp_vault{
    tp_cred_t *creds;
    size_t size;
}tp_vault_t;

static tp_vault_t Vault = {
    .creds = NULL, .size = 0
};

int tp_vault_set(tp_cred_t *credentials, size_t creds_size) {

    if (!credentials)
        return -1;
    
    Vault.creds = credentials;
    Vault.size = creds_size;
    return 0;
}

int tp_vault_get_ms(uint16_t identity, Random_t *S_C_randoms, uint8_t *ms) {

    if (!Vault.creds || !S_C_randoms || !ms)
        return -1;
    
    size_t index = 0;
    while (index < Vault.size && Vault.creds[index].identity != identity)
        index++;
    
    if (index < Vault.size){
        uint8_t pre_master_secret[4 + 2*MAX_PSK_LEN];
        uint16_t psk_len = Vault.creds[index].psk_len;
        size_t pre_master_secret_len = 4 + 2*psk_len;
        *((uint16_t *)&pre_master_secret) = host_htobe16(psk_len);
        host_memset(&pre_master_secret[2],0,psk_len);
        *((uint16_t *)&pre_master_secret[2+psk_len]) = host_htobe16(psk_len);
        host_memcpy(&pre_master_secret[4+psk_len],
                    (void *)Vault.creds[index].psk, psk_len);

        Random_t C_S_randoms[2] = {S_C_randoms[1], S_C_randoms[0]};

        tls_prf_sha256(pre_master_secret, pre_master_secret_len,
                        "master secret",(uint8_t *)C_S_randoms, 2*sizeof(Random_t), ms, 48);
        return 0;
    }
    else return -1;
}