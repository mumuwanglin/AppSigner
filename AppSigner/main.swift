//
//  main.swift
//  AppSigner
//
//  Created by mumu on 2022/9/21.
//

import Darwin
import Foundation

class AppSigner {
    
    // MARK: - 参数
    /// 描述文件地址
    var provisioningFile = ""
    /// 证书名称
    var signingCertificate = ""
    /// 需要签名的 IPA 地址
    var inputFile = ""
    /// 重签名输出文件
    var outFile = ""            
    
    // MARK: - 属性
    var tempFolder: String = ""
    var workingDirectory: String = ""
    var eggDirectory: String = ""
    var payloadDirectory: String = ""
    var entitlementsPlist: String = ""
    
    func printUsage() {
        print("""
Usage:
    AppSigner
OPTIONS:
    -p mobileprovision path
    -k certificate name
    -i need sign ipa path
    -o out put ipa path
    -h display available options
""")
        exit(1)
    }
    
    /// 参数解析
    func getopt() {
        if CommandLine.arguments.isEmpty { printUsage() }
        // 解析
        while case let option = Darwin.getopt(CommandLine.argc, CommandLine.unsafeArgv, "p:k:i:o:h"), option != -1 {
            switch UnicodeScalar(CUnsignedChar(option)) {
            case "p":
                provisioningFile = String(cString: optarg)
            case "k":
                signingCertificate = String(cString: optarg)
            case "i":
                inputFile = String(cString: optarg)
            case "o":
                outFile = String(cString: optarg)
            case "h":
                printUsage()
            default:
                printUsage()
                fatalError("Unknown Option")
            }
        }
        
        // 判断参数是否合法
        if !inputFile.isEmpty, !fileManager.fileExists(atPath: inputFile) {
            fatalError("IPA Not Exist")
        }
        if outFile.isEmpty {
            fatalError("Out File Can Not Be Empty")
        }
        if !provisioningFile.isEmpty, !fileManager.fileExists(atPath: provisioningFile) {
            fatalError("Mobile Provision Not Exist")
        }
    }
    
    
    /// 创建临时工作空间
    func createWorkSpace() {
        if let tmpFolder = makeTempFolder() {
            tempFolder = tmpFolder
            print("workspace: \(tempFolder)")
        } else {
           fatalError("Error creating temp folder")
        }
        
        workingDirectory = tempFolder.stringByAppendingPathComponent("out")
        eggDirectory = tempFolder.stringByAppendingPathComponent("eggs")
        payloadDirectory = workingDirectory.stringByAppendingPathComponent("Payload/")
        entitlementsPlist = tempFolder.stringByAppendingPathComponent("entitlements.plist")
    }
    
    
    /// 解压 IPA 文件
    func unzipIPA() -> String? {
        // 解压文件
        do {
            try fileManager.createDirectory(atPath: workingDirectory, withIntermediateDirectories: true, attributes: nil)
            let unzipTask = unzip(inputFile, outputPath: workingDirectory)
            if unzipTask.status != 0 {
                cleanup(tempFolder)
                fatalError("Error extracting ipa file")
            }
        } catch let error as NSError {
            print(error)
        }
        
        // 查找 .app 文件
        let findTask = Process().execute(findPath, workingDirectory: payloadDirectory, arguments: [".", "-name", "*.app"])
        if findTask.status != 0 {
            print("did not find .app file")
            return nil
        } else {
            return payloadDirectory.stringByAppendingPathComponent(findTask.output.lastPathComponent.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
    
    func generateFileSignFunc(_ payloadDirectory:String, entitlementsPath: String, signingCertificate: String)->((_ file:String)->Void){
           let useEntitlements: Bool = ({
               if fileManager.fileExists(atPath: entitlementsPath) {
                   return true
               }
               return false
           })()

           func shortName(_ file: String, payloadDirectory: String)->String{
               return String(file[payloadDirectory.endIndex...])
           }

           func beforeFunc(_ file: String, certificate: String, entitlements: String?){
               print("Codesigning \(shortName(file, payloadDirectory: payloadDirectory))\(useEntitlements ? " with entitlements":"")")
           }

           func afterFunc(_ file: String, certificate: String, entitlements: String?, codesignOutput: AppSignerTaskOutput){
               if codesignOutput.status != 0 {
                   print("Error codesigning \(shortName(file, payloadDirectory: payloadDirectory))")
               }
           }

           func output(_ file:String){
               codeSign(file, certificate: signingCertificate, entitlements: entitlementsPath, before: beforeFunc, after: afterFunc)
           }
           return output
    }
    
    func sign(_ appBundlePath: String) {
        let appBundleInfoPlist = appBundlePath.stringByAppendingPathComponent("Info.plist")
        let appBundleProvisioningFilePath = appBundlePath.stringByAppendingPathComponent("embedded.mobileprovision")
        
        /// 删除 Info.plist 中的 CFBundleResourceSpecification
        print("Delete CFBundleResourceSpecification from Info.plist")
        let _ = Process().execute(defaultsPath, workingDirectory: nil, arguments: ["delete",appBundleInfoPlist,"CFBundleResourceSpecification"])
        
        /// 创建 ExportOptions.plist 文件
        if fileManager.fileExists(atPath: appBundleProvisioningFilePath) {
            do {
                //  delete 老的 mobileprovision
                try fileManager.removeItem(atPath: appBundleProvisioningFilePath)
                // copy 新的 mobileprovision
                try fileManager.copyItem(atPath: provisioningFile, toPath: appBundleProvisioningFilePath)
            } catch {
                print("Error deleting embedded.mobileprovision")
                cleanup(tempFolder)
            }
        }
        
        
        if let profile = ProvisioningProfile(filename: provisioningFile), let entitlements = profile.getEntitlementsPlist() {
            do {
                try entitlements.write(toFile: entitlementsPlist, atomically: false, encoding: .utf8)
                print("Saved entitlements to \(entitlementsPlist)")
            } catch let error as NSError {
                fatalError("Error writing entitlements.plist, \(error.localizedDescription)")
            }
        }
        
        /// 确保 MachO 文件有可执行权限
        if let bundleExecutable = getPlistKey(appBundleInfoPlist, keyName: "CFBundleExecutable"){
            _ = Process().execute(chmodPath, workingDirectory: nil, arguments: ["755", appBundlePath.stringByAppendingPathComponent(bundleExecutable)])
        }
        
        
        /// 开始签名
        let eggSigningFunction = generateFileSignFunc(eggDirectory, entitlementsPath: entitlementsPlist, signingCertificate: signingCertificate)
        let signingFunction = generateFileSignFunc(payloadDirectory, entitlementsPath: entitlementsPlist, signingCertificate: signingCertificate)
        
        var eggCount: Int = 0
        func signEgg(_ eggFile: String){
            eggCount += 1

            let currentEggPath = eggDirectory.stringByAppendingPathComponent("egg\(eggCount)")
            let shortName = eggFile[payloadDirectory.endIndex...]
            print("Extracting \(shortName)")
            if unzip(eggFile, outputPath: currentEggPath).status != 0 {
                return
            }
            recursiveDirectorySearch(currentEggPath, extensions: ["egg"], found: signEgg)
            recursiveDirectorySearch(currentEggPath, extensions: signableExtensions, found: eggSigningFunction)
            print("Compressing \(shortName)")
            _ = zip(currentEggPath, outputFile: eggFile)
        }
        
        recursiveDirectorySearch(appBundlePath, extensions: ["egg"], found: signEgg)
        recursiveDirectorySearch(appBundlePath, extensions: signableExtensions, found: signingFunction)
        signingFunction(appBundlePath)
        
        // 查看签名信息
        let verificationTask = Process().execute(codesignPath, workingDirectory: nil, arguments: ["-v",appBundlePath])
        if verificationTask.status != 0 {
            print("Error verifying code signature")
        } else {
            print(verificationTask.output)
        }
    }
    
    // 打 IPA 包
    func package() {
        print("begin package.......")
        let zipTask = zip(workingDirectory, outputFile: outFile)
        if zipTask.status != 0 {
            fatalError("Error packaging IPA")
        }
        // 打包完成,清理缓存
        cleanup(tempFolder)
    }
    
    /// 开始签名
    func signing() {
        // 参数解析
        getopt()
        // 创建临时工作空间
        createWorkSpace()
        // 解压 IPA 文件
        let appBundlePath = unzipIPA()
        // 开始签名
        sign(appBundlePath!)
        // 打包
        package()
        
        print("Done, output at \(outFile)")
    }
    
}

AppSigner().signing()
