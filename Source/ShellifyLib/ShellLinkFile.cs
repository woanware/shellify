/*
    Shellify, .NET implementation of Shell Link (.LNK) Binary File Format
    Copyright (C) 2010 Sebastien LEBRETON

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Shellify.Core;
using Shellify.ExtraData;
using Shellify.IO;

namespace Shellify
{
	public class ShellLinkFile : IHasIDList
	{
        public static readonly DateTime WindowsEpoch = new DateTime(1601, 1, 1, 0, 0, 0, 0);

        public ShellLinkHeader Header { get; set; }
		public IList<ExtraDataBlock> ExtraDataBlocks { get; set; }
		public IList<ShItemID> ShItemIDs { get; set; }


        private LinkInfo _linkInfo;
        public LinkInfo LinkInfo
        {
            get
            {
                return _linkInfo;
            }
            set
            {
                _linkInfo = value;
                UpdateHeaderFlags(value, LinkFlags.HasLinkInfo);
            }
        }

        private string _name;
        public string Name
        {
            get
            {
                return _name;
            }
            set
            {
                _name = value;
                UpdateHeaderFlags(value, LinkFlags.HasName);
            }
        }

        private string _relativePath;
        public string RelativePath
        {
            get
            {
                return _relativePath;
            }
            set
            {
                _relativePath = value;
                UpdateHeaderFlags(value, LinkFlags.HasRelativePath);
            }
        }

        private string _workingDirectory;
        public string WorkingDirectory
        {
            get
            {
                return _workingDirectory;
            }
            set
            {
                _workingDirectory = value;
                UpdateHeaderFlags(value, LinkFlags.HasWorkingDir);
            }
        }

        private string _arguments;
        public string Arguments
        {
            get
            {
                return _arguments;
            }
            set
            {
                _arguments = value;
                UpdateHeaderFlags(value, LinkFlags.HasArguments);
            }
        }

        private string _iconLocation;
        public string IconLocation 
        {
            get
            {
                return _iconLocation;
            }
            set
            {
                _iconLocation = value;
                UpdateHeaderFlags(value, LinkFlags.HasIconLocation);
            }
        }

        public ShellLinkFile()
        {
            Header = new ShellLinkHeader();
            ExtraDataBlocks = new List<ExtraDataBlock>();
            ShItemIDs = new List<ShItemID>();
        }

        private void UpdateHeaderFlags(object item, LinkFlags flag)
        {
            if (((item is string) && string.IsNullOrEmpty(item as string)) || (item == null))
            {
                Header.LinkFlags &= ~flag;
            }
            else
            {
                Header.LinkFlags |= flag;
            }
        }

        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            if (Header != null) builder.AppendLine(Header.ToString());
            if (LinkInfo != null) builder.AppendLine(LinkInfo.ToString());
            if (ExtraDataBlocks != null)
            {
                foreach (ExtraDataBlock block in ExtraDataBlocks)
                {
                    builder.AppendLine(block.ToString());
                }
            }
            if (ShItemIDs != null)
            {
                foreach (ShItemID shitem in ShItemIDs)
                {
                    builder.AppendLine(shitem.ToString());
                }
            }
            builder.AppendLine(">>File");
            builder.AppendFormat("Name: {0}", Name); builder.AppendLine();
            builder.AppendFormat("RelativePath: {0}", RelativePath); builder.AppendLine();
            builder.AppendFormat("WorkingDirectory: {0}", WorkingDirectory); builder.AppendLine();
            builder.AppendFormat("Arguments: {0}", Arguments); builder.AppendLine();
            builder.AppendFormat("IconLocation: {0}", IconLocation); builder.AppendLine();
            return builder.ToString();
        }

		public static ShellLinkFile Load(string filename)
		{
			ShellLinkFile result = new ShellLinkFile();
            using (FileStream stream = new FileStream(filename, FileMode.Open))
            {
                using (BinaryReader binaryReader = new BinaryReader(stream))
                {
                    ShellLinkFileHandler reader = new ShellLinkFileHandler(result);
                    reader.ReadFrom(binaryReader);
                    return result;
                }
            }
		}

        public static ShellLinkFile Load(byte[] data)
        {
            ShellLinkFile result = new ShellLinkFile();
            using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(data)))
            {
                ShellLinkFileHandler reader = new ShellLinkFileHandler(result);
                reader.ReadFrom(binaryReader);
                return result;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="filename"></param>
        /// <returns></returns>
        public static List<ShellLinkFile> LoadJumpList(string filename)
        {
            List<ShellLinkFile> results = new List<ShellLinkFile>();
            using (FileStream stream = new FileStream(filename, FileMode.Open, FileAccess.Read))
            using (BinaryReader binaryReader = new BinaryReader(stream))
            {
                bool process = true;
                do
                {
                    // Seek until we get to a valid looking LNK header
                    bool search = true;
                    do
                    {
                        if (binaryReader.BaseStream.Position + 4 > binaryReader.BaseStream.Length)
                        {
                            return results;
                        }

                        byte[] data = new byte[4];

                        binaryReader.Read(data, 0, 4);

                        int ret = BitConverter.ToInt32(data, 0);
                        if (ret != 76) // Default LNK header length
                        {
                            continue;
                        }

                        if (binaryReader.BaseStream.Position + 16 > binaryReader.BaseStream.Length)
                        {
                            return results;
                        }

                        // Check the LNK file GUID e.g. {00021401-0000-0000-00C0-000000000046} or {01h,14h,02h,00h,00h,00h,00h,00h,C0h,00h,00h,00h,00h,00h,46h}
                        data = new byte[16];
                        binaryReader.Read(data, 0, 16);

                        if (ArraysEqual(data, LNK_GUID) == true)
                        {
                            binaryReader.BaseStream.Seek(-20, SeekOrigin.Current);

                            ShellLinkFile result = new ShellLinkFile();
                            ShellLinkFileHandler reader = new ShellLinkFileHandler(result);
                            reader.ReadFrom(binaryReader);

                            if (result.Header.CreationTime != DateTime.MinValue &
                                result.Header.AccessTime != DateTime.MinValue &
                                result.Header.WriteTime != DateTime.MinValue &
                                result.Header.CreationTime != ShellLinkFile.WindowsEpoch &
                                result.Header.AccessTime != ShellLinkFile.WindowsEpoch &
                                result.Header.WriteTime != ShellLinkFile.WindowsEpoch)
                            {
                                results.Add(result);
                                break;
                            }
                        }

                        // If we get this far then we have read 20 bytes, so lets go back 19 bytes and start again
                        binaryReader.BaseStream.Seek(-19, SeekOrigin.Current);
                    }
                    while (search == true);
                }
                while (process == true);

                return results;
            }
        }

        internal static readonly byte[] LNK_GUID = { 1, 20, 2, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70 };

        /// <summary>
        /// 
        /// </summary>
        /// <param name="array1"></param>
        /// <param name="array2"></param>
        /// <returns></returns>
        private static bool ArraysEqual(Array array1, 
                                        Array array2)
        {
            if (array1 == array2)
            {
                return true;
            }

            if (array1 == null || array2 == null)
            {
                return false;
            }

            if (array1.Length != array2.Length)
            {
                return false;
            }

            IList list1 = array1;
            IList list2 = array2;

            for (int index = 0; index < array1.Length; index++)
            {
                if (list1[index].Equals(list2[index]) == false)
                {
                    return false;
                }
            }

            return true;
        }

        public static FileSystemInfo SetFileSystemInfo(ShellLinkFile slf, string target)
        {
            FileSystemInfo targetInfo;
            if (Directory.Exists(target))
            {
                targetInfo = new DirectoryInfo(target);
            }
            else
            {
                targetInfo = new FileInfo(target);
            }

            if (targetInfo.Exists)
            {
                slf.Header.FileAttributes = targetInfo.Attributes;
                slf.Header.AccessTime = targetInfo.LastAccessTime;
                slf.Header.CreationTime = targetInfo.CreationTime;
                slf.Header.WriteTime = targetInfo.LastWriteTime;
                if (targetInfo is FileInfo)
                {
                    slf.Header.FileSize = Convert.ToInt32((targetInfo as FileInfo).Length);
                }
            }
            return targetInfo;
        }

        public static ShellLinkFile CreateRelative(string baseDirectory, string relativeTarget)
        {
            if (Path.IsPathRooted(relativeTarget))
            {
                throw new ArgumentException("Target must be relative to base directory !!!");
            }

            ShellLinkFile result = new ShellLinkFile();

            SetFileSystemInfo(result, Path.Combine(baseDirectory, relativeTarget));
            result.Header.ShowCommand = ShowCommand.Normal;

            result.RelativePath = relativeTarget;
            result.WorkingDirectory = ".";

            return result;
        }

        public static ShellLinkFile CreateAbsolute(string target)
        {
            ShellLinkFile result = new ShellLinkFile();

            FileSystemInfo targetInfo = SetFileSystemInfo(result, target);
            result.Header.ShowCommand = ShowCommand.Normal;

            result.RelativePath = targetInfo.FullName;
            if (targetInfo is FileInfo)
            {
                result.WorkingDirectory = (targetInfo as FileInfo).DirectoryName;
            }
            else
            {
                result.WorkingDirectory = targetInfo.FullName;
            }

            return result;
        }

        public void SaveAs(string filename)
        {
            using (FileStream stream = new FileStream(filename, FileMode.Create))
            {
                using (BinaryWriter binaryWriter = new BinaryWriter(stream))
                {
                    ShellLinkFileHandler writer = new ShellLinkFileHandler(this);
                    writer.WriteTo(binaryWriter);
                }
            }
        }
		
	}
}
