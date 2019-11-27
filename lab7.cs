using System;

namespace ISM.DiffieHellmanAlgorithm
{
    /* Info
     * https://ru.wikipedia.org/wiki/%D0%9F%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB_%D0%94%D0%B8%D1%84%D1%84%D0%B8_%E2%80%94_%D0%A5%D0%B5%D0%BB%D0%BB%D0%BC%D0%B0%D0%BD%D0%B0
     * https://habrahabr.ru/post/151599/
     */
    public class DiffieHellmanAlgorithmCrypto
    {
        #region Public Fields

        public int X { get; private set; }
        public int Y { get; private set; }

        #endregion

        #region Private Fields

        private static readonly int p = 79;
        private static readonly int g = 7;

        #endregion

        public DiffieHellmanAlgorithmCrypto(int x)
        {
            if (x > p)
                throw new ArgumentOutOfRangeException($"{nameof(x)} more then {nameof(p)}");

            X = x;
            Y = modFrom1ToB(p, g, X);
        }

        #region Public Methods

        public string Encode(string value, int otherY) =>
            EncodeAlgorithm(value, otherY);

        public string Decode(string value, int otherX) =>
            DecodeAlgorithm(value, otherX);

        #endregion

        #region Private Methods

        private string EncodeAlgorithm(string value, int otherY)
        {
            int Sa = modFrom1ToB(p, otherY, X);
            int k;
            string resultValue = string.Empty;

            for (int i = 0; i < value.Length; i++)
            {
                k = value[i] + Sa;

                while (k > 122)
                    k -= 26;

                resultValue += (char)k;
            }

            return resultValue;
        }

        private string DecodeAlgorithm(string value, int otherX)
        {
            int Sb = modFrom1ToB(p, Y, otherX);
            int k;
            string resultValue = string.Empty;

            for (int i = 0; i < value.Length; i++)
            {
                k = value[i] - Sb;

                while (k < 97)
                    k += 26;

                resultValue += (char)k;
            }

            return resultValue;
        }

        private static int modFrom1ToB(int p, int a, int b)
        {
            var resultMod = 1;

            for (var i = 1; i <= b; i++)
                resultMod = (resultMod * a) % p;

            return resultMod;
        }

        #endregion
    }
}
