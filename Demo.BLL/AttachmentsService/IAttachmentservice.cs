using Microsoft.AspNetCore.Http;

namespace Demo.BLL.AttachmentsService
{
    public interface IAttachmentservice
    {
        string? Upload(IFormFile file, string FolderName);
        bool Delete(string FilePath);
    }
}
