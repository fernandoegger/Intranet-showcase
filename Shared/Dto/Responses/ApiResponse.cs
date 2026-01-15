namespace Shared;

public class ApiResponse<T>
{
    public T? Data { get; set; }
    public bool IsSuccess { get; set; } = true;
    public string Message { get; set; } = string.Empty;
    public Dictionary<string, List<string>>? Errors { get; set; }

    public static ApiResponse<T> Success(T? data, string message = "")
    {
        return new ApiResponse<T>
        {
            Data = data, 
            Message = message
        };
    }

    public static ApiResponse<T> Error(string message, Dictionary<string, List<string>>? errors = null)
    {
        return new ApiResponse<T>
        {
            IsSuccess = false,
            Message = message,
            Errors = errors
        };
    }
}