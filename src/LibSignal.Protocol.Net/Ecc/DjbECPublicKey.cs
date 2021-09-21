namespace LibSignal.Protocol.Net.Ecc
{
    using System;
    using System.Numerics;

    using LibSignal.Protocol.Net.Util;


    public class DjbECPublicKey : ECPublicKey
    {

    private readonly byte[] publicKey;

    DjbECPublicKey(byte[] publicKey)
    {
        this.publicKey = publicKey;
    }

    public override byte[] serialize()
    {
        byte[] type = { Curve.DJB_TYPE };
        return ByteUtil.combine(type, publicKey);
    }

    public override int getType()
    {
        return Curve.DJB_TYPE;
    }

    public override bool equals(Object other)
    {
        if (other == null) return false;
        if (!(other instanceof DjbECPublicKey)) return false;

        DjbECPublicKey that = (DjbECPublicKey)other;
        return Arrays.equals(this.publicKey, that.publicKey);
    }

    public override int hashCode()
    {
        return Arrays.hashCode(publicKey);
    }

    public override int compareTo(ECPublicKey another)
    {
        return new BigInteger(publicKey).CompareTo(new BigInteger(((DjbECPublicKey)another).publicKey));
    }

    public byte[] getPublicKey()
    {
        return publicKey;
    }
    }
}