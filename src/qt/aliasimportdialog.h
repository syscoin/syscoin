#ifndef ALIASIMPORTDIALOG_H
#define ALIASIMPORTDIALOG_H
#include <QDialog>
class PlatformStyle;
class QDataWidgetMapper;
class UniValue;
namespace Ui {
    class AliasImportDialog;
}
QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE
/** Dialog for editing an address and associated information.
 */
class AliasImportDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AliasImportDialog(const PlatformStyle *platformStyle, const QModelIndex &idx, QWidget *parent=0);
    ~AliasImportDialog();
private Q_SLOTS:
	bool on_importButton_clicked();
private:
	QDataWidgetMapper *mapper;
    Ui::AliasImportDialog *ui;
	QString alias;

};

#endif // ALIASIMPORTDIALOG_H
