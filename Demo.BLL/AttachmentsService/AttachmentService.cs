using Microsoft.AspNetCore.Http;

namespace Demo.BLL.AttachmentsService
{
    public class AttachmentService : IAttachmentservice
    {
        public string? Upload(IFormFile file, string FolderName)
        {
            List<string> AllowedExtensions = [".png", ".jpg", ".jepg"];
            const int MaxSize = 2_097_152;
            // 1- Check Extensions 
            var Extension = Path.GetExtension(file.FileName);
            if (!AllowedExtensions.Contains(Extension)) return null;
            // 2- Check Size 
            if (file.Length == 0 || file.Length > MaxSize) return null;
            // 3- Get Located Folder Path.
            var FolderPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot\\Files", FolderName);
            // 4- Make Attachment name unique --> GUID 
            var FileName = $"{Guid.NewGuid()}_{file.FileName}";
            // 5- Get File Path
            var FilePath = Path.Combine(FolderPath, FileName);
            // 6- Create file stream (unmanaged) 
            using FileStream Fs = new(FilePath, FileMode.Create);
            // 7- Use streame to copy  file
            file.CopyTo(Fs);
            // 8- return file name 
            return FileName;

        }




        public bool Delete(string FilePath)   // FolderPath + FileName
        {
            if (File.Exists(FilePath))
            {
                File.Delete(FilePath);
                return true;
            }
            return false;
        }

    }
}
