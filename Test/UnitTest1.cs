using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NetPasswordHash;
using System;
namespace Test;

[TestClass]
public class UnitTest1
{
    [TestMethod]
    public void TestMethod1()
    {
        var pw = new PasswordHash();
        string cha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random r = new Random();
        int rInt = r.Next(8, 1000); //for ints
        string pass = "";
        for(var i = 0; i< rInt; i++) {
            Random rad = new Random();
            var id = rad.Next(0, cha.Length);
            pass+= cha[id];
        }
        var hash = pw.Generate(pass);
        Console.WriteLine(pass);
        Console.WriteLine(hash);
        var verify = pw.Verify(pass, hash);
        Console.WriteLine(verify);
        Assert.IsTrue(verify, "Password not match");
    }
}