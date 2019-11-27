using System;
using System.Text;
using bint = BigInteger;

namespace ISM.GOST3410
{
    /* Info
     * https://habrahabr.ru/post/136022/
     */
    public class GOST3410Crypto
    {
        #region Private Fields

        private readonly bint _a;
        private readonly bint _b;
        private readonly bint _n;
        private readonly bint _p;
        private readonly byte[] _xG;

        private CECPoint G = new CECPoint();

        #endregion

        #region Ctors

        public GOST3410Crypto() : this(
            p: new bint("6277101735386680763835789423207666416083908700390324961279", 10),
            a: new bint("-3", 10),
            b: new bint("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
            n: new bint("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
            xG: fromHexStringToByte("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"))
        { }

        public GOST3410Crypto(bint p, bint a, bint b, bint n, byte[] xG)
        {
            _a = a;
            _b = b;
            _n = n;
            _p = p;
            _xG = xG;
        }

        #endregion

        #region Public Methods

        public string GenerateElectronicDigitalSignature(string message, out CECPoint publicKey)
        {
            var privateKey = GeneratePrivateKey(192);
            publicKey = GeneratePublicKey(privateKey);
            var hash = new Stribog(256);

            var H = hash.GetHash(Encoding.Default.GetBytes(message));
            var sign = genDS(H, privateKey);                                                            // Сообщение \"{0}\" имеет следующую ЭЦП: {1}", message, sign

            return sign;
        }

        public bool IsValidElectronicDigitalSignature(string message, string sign, CECPoint publicKey)
        {
            var hash = new Stribog(256);

            byte[] H2 = hash.GetHash(Encoding.Default.GetBytes(message));
            bool result = verifDS(H2, sign, publicKey);

            return result;
        }

        #endregion

        #region Private Methods

        // генерация секретного ключа заданной длины.
        private bint GeneratePrivateKey(int BitSize)
        {
            bint d = new bint();
            do
            {
                d.genRandomBits(BitSize, new Random());
            } while ((d < 0) || (d > _n));
            return d;
        }

        // генерация публичного ключа (с помощью секретного).
        private CECPoint GeneratePublicKey(bint d)
        {
            CECPoint G = gDecompression();
            CECPoint Q = CECPoint.multiply(G, d);
            return Q;
        }

        private static byte[] fromHexStringToByte(string input)
        {
            byte[] data = new byte[input.Length / 2];
            string HexByte = "";
            for (int i = 0; i < data.Length; i++)
            {
                HexByte = input.Substring(i * 2, 2);
                data[i] = Convert.ToByte(HexByte, 16);
            }
            return data;
        }

        // восстановление координат Y из координаты X и бита четности Y.
        private CECPoint gDecompression()
        {
            byte y = _xG[0];
            byte[] x = new byte[_xG.Length - 1];
            Array.Copy(_xG, 1, x, 0, _xG.Length - 1);
            bint Xcord = new bint(x);
            bint temp = (Xcord * Xcord * Xcord + _a * Xcord + _b) % _p;
            bint beta = modSqrt(temp, _p);
            bint Ycord = new bint();
            if ((beta % 2) == (y % 2))
                Ycord = beta;
            else
                Ycord = _p - beta;
            CECPoint G = new CECPoint();
            G.a = _a;
            G.b = _b;
            G.fieldChar = _p;
            G.x = Xcord;
            G.y = Ycord;
            this.G = G;
            return G;
        }

        // вычисление квадратоного корня по модулю простого числа q.
        private bint modSqrt(bint a, bint q)
        {
            bint b = new bint();
            do
            {
                b.genRandomBits(255, new Random());
            }
            while (legendre(b, q) == 1);

            bint s = 0;
            bint t = q - 1;
            while ((t & 1) != 1)
            {
                s++;
                t = t >> 1;
            }

            bint InvA = a.modInverse(q);
            bint c = b.modPow(t, q);
            bint r = a.modPow(((t + 1) / 2), q);
            bint d = new bint();
            for (int i = 1; i < s; i++)
            {
                bint temp = 2;
                temp = temp.modPow((s - i - 1), q);
                d = (r.modPow(2, q) * InvA).modPow(temp, q);
                if (d == (q - 1))
                    r = (r * c) % q;
                c = c.modPow(2, q);
            }
            return r;
        }

        // вычисление символа Лежандра.
        private bint legendre(bint a, bint q)
        {
            return a.modPow((q - 1) / 2, q);
        }

        // формирование цифровой подписи.
        private string genDS(byte[] h, bint d)
        {
            bint a = new bint(h);
            bint e = a % _n;
            if (e == 0)
                e = 1;
            bint k = new bint();
            CECPoint C = new CECPoint();
            bint r = new bint();
            bint s = new bint();
            do
            {
                do
                {
                    k.genRandomBits(_n.bitCount(), new Random());
                }
                while ((k < 0) || (k > _n));

                C = CECPoint.multiply(G, k);
                r = C.x % _n;
                s = ((r * d) + (k * e)) % _n;
            }
            while ((r == 0) || (s == 0));

            string Rvector = padding(r.ToHexString(), _n.bitCount() / 4);
            string Svector = padding(s.ToHexString(), _n.bitCount() / 4);
            return Rvector + Svector;
        }

        // проверка цифровой подписи.
        private bool verifDS(byte[] H, string sign, CECPoint Q)
        {
            string Rvector = sign.Substring(0, _n.bitCount() / 4);
            string Svector = sign.Substring(_n.bitCount() / 4, _n.bitCount() / 4);
            bint r = new bint(Rvector, 16);
            bint s = new bint(Svector, 16);

            if ((r < 1) || (r > (_n - 1)) || (s < 1) || (s > (_n - 1)))
                return (false);

            bint a = new bint(H);
            bint e = a % _n;
            if (e == 0)
                e = 1;

            bint v = e.modInverse(_n);
            bint z1 = (s * v) % _n;
            bint z2 = _n + ((-(r * v)) % _n);
            this.G = gDecompression();
            CECPoint A = CECPoint.multiply(G, z1);
            CECPoint B = CECPoint.multiply(Q, z2);
            CECPoint C = A + B;
            bint R = C.x % _n;
            if (R == r)
                return (true);
            else
                return (false);
        }

        // дополнить подпись нулями слева до длины n, 
        // где n - длина модуля в битах.
        private string padding(string input, int size)
        {
            if (input.Length < size)
            {
                do
                {
                    input = "0" + input;
                }
                while (input.Length < size);
            }
            return (input);
        }

        #endregion

        public struct CECPoint
        {
            public bint a;
            public bint b;
            public bint x;
            public bint y;
            public bint fieldChar;

            private CECPoint(CECPoint p)
            {
                a = p.a;
                b = p.b;
                x = p.x;
                y = p.y;
                fieldChar = p.fieldChar;
            }

            #region Public Operation Methods

            //сложение пары точек.
            public static CECPoint operator +(CECPoint p1, CECPoint p2)
            {
                CECPoint res = new CECPoint();
                res.a = p1.a;
                res.b = p1.b;
                res.fieldChar = p1.fieldChar;

                bint dx = p2.x - p1.x;
                bint dy = p2.y - p1.y;

                if (dx < 0)
                    dx += p1.fieldChar;
                if (dy < 0)
                    dy += p1.fieldChar;

                bint t = (dy * dx.modInverse(p1.fieldChar)) % p1.fieldChar;

                if (t < 0)
                    t += p1.fieldChar;

                res.x = (t * t - p1.x - p2.x) % p1.fieldChar;
                res.y = (t * (p1.x - res.x) - p1.y) % p1.fieldChar;

                if (res.x < 0)
                    res.x += p1.fieldChar;
                if (res.y < 0)
                    res.y += p1.fieldChar;

                return (res);
            }

            //удвоение точки.
            public static CECPoint doubling(CECPoint p)
            {
                CECPoint res = new CECPoint();

                res.a = p.a;
                res.b = p.b;
                res.fieldChar = p.fieldChar;

                bint dx = 2 * p.y;
                bint dy = 3 * p.x * p.x + p.a;

                if (dx < 0)
                    dx += p.fieldChar;
                if (dy < 0)
                    dy += p.fieldChar;

                bint t = (dy * dx.modInverse(p.fieldChar)) % p.fieldChar;
                res.x = (t * t - p.x - p.x) % p.fieldChar;
                res.y = (t * (p.x - res.x) - p.y) % p.fieldChar;

                if (res.x < 0)
                    res.x += p.fieldChar;
                if (res.y < 0)
                    res.y += p.fieldChar;

                return (res);
            }

            //умножение точки на число.
            public static CECPoint multiply(CECPoint p, bint c)
            {
                CECPoint res = p;
                c = c - 1;
                while (c != 0)
                {
                    if ((c % 2) != 0)
                    {
                        if ((res.x == p.x) || (res.y == p.y))
                            res = doubling(res);
                        else
                            res = res + p;
                        c = c - 1;
                    }

                    c = c / 2;
                    p = doubling(p);
                }

                return (res);
            }

            #endregion
        }
    }
}
