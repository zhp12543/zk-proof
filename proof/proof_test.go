// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package proof

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"github.com/zhp12543/zk-proof/curve"
	"github.com/zhp12543/zk-proof/mta"
	"testing"
	"time"
)

func TestProof(t *testing.T)  {
	param, err := GeneratePreParams(time.Second * 120)
	fmt.Println(err)

	jdata, err := json.Marshal(param)
	fmt.Println(string(jdata))
	var param1 PaillierParams
	err = json.Unmarshal(jdata, &param1)

	dln1, dln2, err := param1.DlnProof()
	fmt.Println(err)
	fmt.Println(param1.VerifyDln(dln1, dln2))

	param2, err := GeneratePreParams(time.Second * 120)
	fmt.Println(err)

	jdata, err = json.Marshal(param2)
	fmt.Println(string(jdata))
	var param3 PaillierParams
	err = json.Unmarshal(jdata, &param3)

	dln1, dln2, err = param3.DlnProof()
	fmt.Println(err)
	fmt.Println(param3.VerifyDln(dln1, dln2))


	ec := elliptic.P256()
	k := curve.MustGetRandomInt(ec.Params().N.BitLen())
	fmt.Println("k: ", k)
	cA, pi, err := mta.AliceInit(
		ec,
		// 自己的公钥
		&param1.PaillierSK.PublicKey,
		k,
		// 其它节点的参数
		param3.NTildei,
		param3.H1i,
		param3.H2i)

	fmt.Println(param1.PaillierSK.Decrypt(cA))
	fmt.Println("AliceInit err:", err)

	gamma := curve.MustGetRandomInt(ec.Params().N.BitLen())
	_, c1ji, _, pi1ji, err := mta.BobMid(
		ec,
		&param1.PaillierSK.PublicKey,
		pi,
		// 计算R的随机数
		gamma,
		// 同态加密的kJ
		cA,
		param1.NTildei,
		param1.H1i,
		param1.H2i,
		param3.NTildei,
		param3.H1i,
		param3.H2i)

	fmt.Println("BobMid err:", err)
	_, err = mta.AliceEnd(
		ec,
		&param1.PaillierSK.PublicKey,
		// r2msg.GetC1() 的zk证明
		pi1ji,
		param1.H1i,
		param1.H2i,
		cA,
		// 其它节点传过来的 同态加密的 k* dJ -v
		c1ji,
		param1.NTildei,
		param1.PaillierSK)
	fmt.Println("AliceEnd err:", err)
}