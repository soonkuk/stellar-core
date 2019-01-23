// Copyright 2016 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/SignerKeyUtils.h"

#include "crypto/SHA.h"
#include "transactions/TransactionFrame.h"

namespace stellar
{

namespace SignerKeyUtils
{

// transaction을 parameter로 전달했을 때 transaction의 hash를 signerkey의 preAuthTx값으로 설정하는 함수
SignerKey
preAuthTxKey(TransactionFrame const& tx)
{
    SignerKey sk;
    sk.type(SIGNER_KEY_TYPE_PRE_AUTH_TX);
    sk.preAuthTx() = tx.getContentsHash();
    return sk;
}

// byteslice를 전달하면 byteslice의 hash값을 signerkey의 hashX값으로 설정하는 함수
SignerKey
hashXKey(ByteSlice const& bs)
{
    SignerKey sk;
    sk.type(SIGNER_KEY_TYPE_HASH_X);
    sk.hashX() = sha256(bs);
    return sk;
}
}
}
