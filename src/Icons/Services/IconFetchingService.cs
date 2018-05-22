﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Bit.Icons.Models;
using HtmlAgilityPack;

namespace Bit.Icons.Services
{
    public class IconFetchingService : IIconFetchingService
    {
        private static HashSet<string> _iconRels = new HashSet<string> { "icon", "apple-touch-icon", "shortcut icon" };
        private static HashSet<string> _iconExtensions = new HashSet<string> { ".ico", ".png", ".jpg", ".jpeg" };
        private static readonly HttpClient _httpClient = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        });
        private static string _pngMediaType = "image/png";
        private static byte[] _pngHeader = new byte[] { 137, 80, 78, 71 };
        private static string _icoMediaType = "image/x-icon";
        private static string _icoAltMediaType = "image/vnd.microsoft.icon";
        private static byte[] _icoHeader = new byte[] { 00, 00, 01, 00 };
        private static string _jpegMediaType = "image/jpeg";
        private static byte[] _jpegHeader = new byte[] { 255, 216, 255 };
        private static string _octetMediaType = "application/octet-stream";
        private static readonly HashSet<string> _allowedMediaTypes = new HashSet<string>{
            _pngMediaType,
            _icoMediaType,
            _icoAltMediaType,
            _jpegMediaType,
            _octetMediaType
        };

        public async Task<IconResult> GetIconAsync(string domain)
        {
            var uri = new Uri($"http://{domain}");
            var response = await GetAndFollowAsync(uri, 2);
            if(response == null || !response.IsSuccessStatusCode)
            {
                uri = new Uri($"https://{domain}");
                response = await GetAndFollowAsync(uri, 2);
            }

            if(response?.Content == null || !response.IsSuccessStatusCode)
            {
                return null;
            }

            if(response.Content.Headers?.ContentType?.MediaType != "text/html")
            {
                return null;
            }

            uri = response.RequestMessage.RequestUri;
            var html = await response.Content.ReadAsStringAsync();
            var doc = new HtmlDocument();
            doc.LoadHtml(html);
            if(doc.DocumentNode == null)
            {
                return null;
            }

            var icons = new List<IconResult>();
            var links = doc.DocumentNode.SelectNodes(@"//link[@href]");
            if(links != null)
            {
                foreach(var link in links)
                {
                    var hrefAttr = link.Attributes["href"];
                    if(string.IsNullOrWhiteSpace(hrefAttr?.Value))
                    {
                        continue;
                    }

                    var relAttr = link.Attributes["rel"];
                    if(relAttr != null && _iconRels.Contains(relAttr.Value))
                    {
                        icons.Add(new IconResult(hrefAttr.Value, link));
                    }
                    else
                    {
                        var extension = Path.GetExtension(hrefAttr.Value);
                        if(_iconExtensions.Contains(extension))
                        {
                            icons.Add(new IconResult(hrefAttr.Value, link));
                        }
                    }
                }
            }

            var iconResultTasks = new List<Task>();
            foreach(var icon in icons)
            {
                Uri iconUri = null;
                if(Uri.TryCreate(icon.Path, UriKind.Relative, out Uri relUri))
                {
                    iconUri = new Uri($"{uri.Scheme}://{uri.Host}/{relUri.OriginalString}");
                }
                else if(Uri.TryCreate(icon.Path, UriKind.Absolute, out Uri absUri))
                {
                    iconUri = absUri;
                }

                if(iconUri != null)
                {
                    var task = GetIconAsync(iconUri).ContinueWith(async (r) =>
                    {
                        var result = await r;
                        if(result != null)
                        {
                            icon.Path = iconUri.ToString();
                            icon.Icon = result.Icon;
                        }
                    });
                    iconResultTasks.Add(task);
                }
            }

            await Task.WhenAll(iconResultTasks);
            if(!icons.Any(i => i.Icon != null))
            {
                var faviconUri = new Uri($"{uri.Scheme}://{uri.Host}/favicon.ico");
                var result = await GetIconAsync(faviconUri);
                if(result != null)
                {
                    icons.Add(result);
                }
                else
                {
                    return null;
                }
            }

            return icons.Where(i => i.Icon != null).OrderBy(i => i.Priority).First();
        }

        private async Task<IconResult> GetIconAsync(Uri uri)
        {
            var response = await GetAndFollowAsync(uri, 2);
            if(response?.Content?.Headers == null || !response.IsSuccessStatusCode)
            {
                return null;
            }

            var format = response.Content.Headers?.ContentType?.MediaType;
            if(format == null || !_allowedMediaTypes.Contains(format))
            {
                return null;
            }

            var bytes = await response.Content.ReadAsByteArrayAsync();
            if(format == _octetMediaType)
            {
                if(HeaderMatch(bytes, _icoHeader))
                {
                    format = _icoMediaType;
                }
                else if(HeaderMatch(bytes, _pngHeader))
                {
                    format = _pngMediaType;
                }
                else if(HeaderMatch(bytes, _jpegHeader))
                {
                    format = _jpegMediaType;
                }
                else
                {
                    return null;
                }
            }

            return new IconResult(uri, bytes, format);
        }

        private async Task<HttpResponseMessage> GetAndFollowAsync(Uri uri, int maxRedirectCount)
        {
            var response = await GetAsync(uri);
            if(response == null)
            {
                return null;
            }
            return await FollowRedirectsAsync(response, maxRedirectCount);
        }

        private async Task<HttpResponseMessage> GetAsync(Uri uri)
        {
            var message = new HttpRequestMessage
            {
                RequestUri = uri,
                Method = HttpMethod.Get
            };

            // Let's add some headers to look like we're coming from a web browser request. Some websites
            // will block our request without these.
            message.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36");
            message.Headers.Add("Accept-Language", "en-US,en;q=0.8");
            message.Headers.Add("Cache-Control", "no-cache");
            message.Headers.Add("Pragma", "no-cache");
            message.Headers.Add("Accept", "image/webp,image/apng,image/*,*/*;q=0.8");

            try
            {
                return await _httpClient.SendAsync(message);
            }
            catch
            {
                return null;
            }
        }

        private async Task<HttpResponseMessage> FollowRedirectsAsync(HttpResponseMessage response,
            int maxFollowCount, int followCount = 0)
        {
            if(response.IsSuccessStatusCode || followCount > maxFollowCount)
            {
                return response;
            }

            if(!(response.StatusCode == HttpStatusCode.Redirect ||
                response.StatusCode == HttpStatusCode.MovedPermanently ||
                response.StatusCode == HttpStatusCode.RedirectKeepVerb) ||
                !response.Headers.Contains("Location"))
            {
                return null;
            }

            var locationHeader = response.Headers.GetValues("Location").FirstOrDefault();
            if(!string.IsNullOrWhiteSpace(locationHeader))
            {
                if(!Uri.TryCreate(locationHeader, UriKind.Absolute, out Uri location))
                {
                    if(Uri.TryCreate(locationHeader, UriKind.Relative, out Uri relLocation))
                    {
                        var requestUri = response.RequestMessage.RequestUri;
                        location = new Uri($"{requestUri.Scheme}://{requestUri.Host}/{relLocation.OriginalString}");
                    }
                    else
                    {
                        return null;
                    }
                }

                var newResponse = await GetAsync(location);
                if(newResponse != null)
                {
                    var redirectedResponse = await FollowRedirectsAsync(newResponse, maxFollowCount, followCount++);
                    if(redirectedResponse != null)
                    {
                        return redirectedResponse;
                    }
                }
            }

            return null;
        }

        private bool HeaderMatch(byte[] imageBytes, byte[] header)
        {
            return imageBytes.Length >= header.Length && header.SequenceEqual(imageBytes.Take(header.Length));
        }
    }
}
