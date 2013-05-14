using System;

namespace Shellify
{
    /// <summary>
    /// 
    /// </summary>
    public class Uuid
    {
        #region Member Variables/Properties
        public DateTime Timestamp { get; private set; }
        public string MacAddress { get; private set; }
        public int ClockId { get; private set; }
        #endregion

        #region Constructor
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        public Uuid(string data)
        {
            MacAddress = string.Empty;
            try
            {
                data = data.Replace("-", string.Empty);

                long low = UInt32.Parse(data.Substring(2 * 0, 2 * 4), System.Globalization.NumberStyles.HexNumber);
                long mid = UInt32.Parse(data.Substring(2 * 4, 2 * 2), System.Globalization.NumberStyles.HexNumber);
                long high = UInt32.Parse(data.Substring(2 * 6 + 1, 2 * 2 - 1), System.Globalization.NumberStyles.HexNumber);
                long version = UInt32.Parse(data.Substring(2 * 6, 1), System.Globalization.NumberStyles.HexNumber);

                double time = (high * (Math.Pow(2, 16)) + mid) * (Math.Pow(2, 32)) + low;
                ulong epoc = (ulong)(time / 10000000) - 12219292800;
                double nano = (long)time - ((long)(time / 10000000)) * 10000000;

                DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0);
                Timestamp = epoch.AddSeconds(epoc);

                int clkHi = Int32.Parse(data.Substring(2 * 8, 2 * 1), System.Globalization.NumberStyles.HexNumber);
                int clkLo = Int32.Parse(data.Substring(2 * 9, 2 * 1), System.Globalization.NumberStyles.HexNumber);
                MacAddress = FormatMacAddress(data.Substring(2 * 10, 2 * 6));

                int clock = clkHi * 256;

                ClockId = clock + clkLo;
            }
            catch (Exception){}
        }
        #endregion


        #region Misc Methods
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private string FormatMacAddress(string data)
        {
            if (data.Length != 12)
            {
                return data;
            }

            string temp = string.Empty;
            for (int index = 0; index < 12; index++)
            {
                temp += data.Substring(index, 2);

                if (index != 10)
                {
                    temp += ":";
                }

                index++;
            }

            return temp;
        }
        #endregion
    }
}
