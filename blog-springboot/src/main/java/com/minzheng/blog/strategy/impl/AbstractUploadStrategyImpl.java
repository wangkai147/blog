package com.minzheng.blog.strategy.impl;

import com.minzheng.blog.enums.FileExtEnum;
import com.minzheng.blog.exception.BizException;
import com.minzheng.blog.strategy.UploadStrategy;
import com.minzheng.blog.util.FileUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.util.Objects;

/**
 * 抽象上传模板
 *
 * @author yezhiqiu
 * @date 2021/07/28
 */
@Service
public abstract class AbstractUploadStrategyImpl implements UploadStrategy {

    @Override
    public String uploadFile(MultipartFile file, String path) {
        try {
            // 获取文件md5值
            String md5 = FileUtils.getMd5(file.getInputStream());
            // 获取文件扩展名
            String extName = FileUtils.getExtName(file.getOriginalFilename());
            // 重新生成文件名
            String fileName = md5 + extName;
            // 判断文件是否已经上传
            if (!exists(path + fileName)) {
                InputStream inputStream;
                // 判断上传文件类型（压缩包，图片，音频）
                switch (Objects.requireNonNull(FileExtEnum.getFileExt(extName))) {
                    case JPG:
                    case PNG:
                        // 压缩图片
                        inputStream = FileUtils.compressImage(file.getInputStream(), file.getSize());
                        break;
                    default:
                        inputStream = file.getInputStream();
                        break;
                }
                upload(path, fileName, inputStream);
            }
            return getFileAccessUrl(path + fileName);
        } catch (Exception e) {
            e.printStackTrace();
            throw new BizException("文件上传失败");
        }
    }

    /**
     * 判断文件是否存在
     *
     * @param filePath 文件路径
     * @return {@link Boolean}
     */
    public abstract Boolean exists(String filePath);

    /**
     * 上传
     *
     * @param path        路径
     * @param fileName    文件名
     * @param inputStream 输入流
     * @throws IOException io异常
     */
    public abstract void upload(String path, String fileName, InputStream inputStream) throws IOException;

    /**
     * 获取文件访问url
     *
     * @param filePath 文件路径
     * @return {@link String}
     */
    public abstract String getFileAccessUrl(String filePath);

}