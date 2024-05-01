/* -------------------------------- [alert_] functions ------------------------------- */
/*
*  Functions handling the alert protocol
*/
#ifndef ALERT_H_
#define ALERT_H_

#include "tinypsk.h"
#include "tp_types.h"

/*
*  You can get the length of this message by sizeof
*/
typedef struct Alert_t_ Alert_t;
struct __attribute__ ((__packed__)) Alert_t_{
    AlertLevel_t level;
    AlertDescription_t description;
};

int alert_send(tp_sock_t *s, Alert_t message);
int alert_handle(tp_sock_t *s, Alert_t message);

#endif